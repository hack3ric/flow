use super::Linux;
use crate::bgp::flow::{Bitmask, BitmaskFlags, Component, ComponentKind, Flowspec, Numeric, NumericFlags, Op, Ops};
use crate::bgp::route::{ExtCommunity, Ipv6ExtCommunity, RouteInfo, TrafficFilterAction, TrafficFilterActionKind};
use crate::kernel::rtnl::{RtNetlink, RtNetlinkArgs};
use crate::kernel::{Error, Result};
use crate::net::{Afi, IpPrefix};
use crate::util::{Intersect, TruthTable, grace};
use nftables::batch::Batch;
use nftables::expr::Expression::{Number, String as Str};
use nftables::helper::{
  DEFAULT_NFT, apply_and_return_ruleset_async, apply_ruleset_async, get_current_ruleset_raw_async,
};
use nftables::schema::Nftables as NftablesReq;
use nftables::{expr, schema, stmt, types};
use num_integer::Integer;
use serde::{Deserialize, Serialize};
use smallvec::{SmallVec, smallvec, smallvec_inline};
use std::borrow::Cow;
use std::cmp::{Ordering, min};
use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use std::mem::replace;
use std::net::IpAddr;
use std::ops::{Not, RangeInclusive};

#[derive(Debug, Serialize, Deserialize)]
pub struct Nftables {
  table: Cow<'static, str>,
  chain: Cow<'static, str>,
}

impl Nftables {
  pub async fn new(
    table: impl Into<Cow<'static, str>>,
    chain: impl Into<Cow<'static, str>>,
    hooked: bool,
    priority: i32,
  ) -> Result<Self> {
    let table = table.into();
    let chain = chain.into();
    let mut batch = Batch::new();
    batch.add(schema::NfListObject::Table(schema::Table {
      family: types::NfFamily::INet,
      name: table.clone(),
      ..Default::default()
    }));
    batch.add(schema::NfListObject::Chain(schema::Chain {
      family: types::NfFamily::INet,
      table: table.clone(),
      name: chain.clone(),
      _type: hooked.then_some(types::NfChainType::Filter),
      hook: hooked.then_some(types::NfHook::Input),
      prio: hooked.then_some(priority),
      ..Default::default()
    }));
    apply_ruleset_async(&batch.to_nftables()).await?;
    Ok(Self { table, chain })
  }

  pub fn make_new_rule(&self, stmts: Cow<'static, [stmt::Statement]>) -> schema::NfListObject<'static> {
    schema::NfListObject::Rule(schema::Rule {
      family: types::NfFamily::INet,
      table: self.table.clone(),
      chain: self.chain.clone(),
      expr: stmts,
      ..Default::default()
    })
  }

  pub fn make_new_rule_with_index(
    &self,
    stmts: Cow<'static, [stmt::Statement]>,
    index: u32,
  ) -> schema::NfListObject<'static> {
    schema::NfListObject::Rule(schema::Rule {
      family: types::NfFamily::INet,
      table: self.table.clone(),
      chain: self.chain.clone(),
      expr: stmts,
      handle: Some(index), // `index` seems not working, and `handle` works fine
      ..Default::default()
    })
  }

  #[expect(unused)]
  pub async fn get_current_ruleset_raw(&self) -> Result<String> {
    let args = ["-n", "-s", "list", "chain", "inet", &self.table, &self.chain];
    Ok(get_current_ruleset_raw_async(DEFAULT_NFT, args).await?)
  }

  pub async fn apply_ruleset(&self, n: &NftablesReq<'_>) -> Result<()> {
    Ok(apply_ruleset_async(n).await?)
  }

  pub async fn apply_and_return_ruleset(&self, n: &NftablesReq<'_>) -> Result<NftablesReq<'static>> {
    Ok(apply_and_return_ruleset_async(n).await?)
  }

  fn make_rule_handle(&self, handle: u32) -> schema::NfListObject<'_> {
    schema::NfListObject::Rule(schema::Rule {
      family: types::NfFamily::INet,
      table: self.table.clone(),
      chain: self.chain.clone(),
      handle: Some(handle),
      ..Default::default()
    })
  }

  pub async fn remove_rules(&self, handle: impl IntoIterator<Item = u32>) {
    let rm = NftablesReq {
      objects: handle
        .into_iter()
        .map(|x| schema::NfObject::CmdObject(schema::NfCmd::Delete(self.make_rule_handle(x))))
        .collect(),
    };
    grace(self.apply_ruleset(&rm).await, "failed to remove nftables rules");
  }

  pub async fn terminate(self) {
    let mut batch = Batch::new();
    batch.delete(schema::NfListObject::Chain(schema::Chain {
      family: types::NfFamily::INet,
      table: self.table.clone(),
      name: self.chain.clone(),
      ..Default::default()
    }));
    _ = apply_ruleset_async(&batch.to_nftables()).await;
  }
}

/// Makes sure transport protocol is consistent across components inside a
/// flowspec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
  Tcp,
  Icmp,
  Unknown,
}

type StatementBlock<'a> = SmallVec<[stmt::Statement<'a>; 1]>;
type StatementBranch<'a> = SmallVec<[StatementBlock<'a>; 1]>;

impl Flowspec {
  pub(super) fn to_nft_stmts(&self) -> Result<impl Iterator<Item = Result<StatementBranch<'static>>> + '_> {
    use ComponentKind as CK;

    let set = self.component_set();
    let tcp = set.contains(&CK::TcpFlags);
    let icmp = set.contains(&CK::IcmpType) || set.contains(&CK::IcmpCode);
    let transport = match (tcp, icmp) {
      (false, false) => Transport::Unknown,
      (false, true) => Transport::Icmp,
      (true, false) => Transport::Tcp,
      _ => return Err(Error::MatchNothing),
    };

    let first = make_match(
      stmt::Operator::EQ,
      make_meta(expr::MetaKey::Nfproto),
      Str(if self.afi() == Afi::Ipv4 { "ipv4" } else { "ipv6" }.into()),
    );
    let result = Some(Ok(smallvec_inline![smallvec_inline![first]]))
      .into_iter()
      .chain(self.components().map(move |x| x.to_nft_stmts(self.afi(), transport)))
      .filter(|x| x.is_err() || x.as_ref().is_ok_and(|y| !y.is_empty()));
    Ok(result)
  }
}

impl Component {
  fn to_nft_stmts(&self, afi: Afi, tp: Transport) -> Result<StatementBranch<'static>> {
    use Component::*;
    use Transport::*;

    let ip_ver = if afi == Afi::Ipv4 { "ip" } else { "ip6" };
    let icmp = if afi == Afi::Ipv4 { "icmp" } else { "icmpv6" };
    let (th, tp_code) = match tp {
      Tcp => (Ok("tcp"), Some(6)),
      Icmp => (Err(Error::MatchNothing), Some(if afi == Afi::Ipv4 { 1 } else { 58 })),
      Unknown => (Ok("th"), None),
    };
    let result: StatementBranch = match self {
      &DstPrefix(prefix, 0) => prefix_stmt("daddr", prefix).into_iter().map(|x| smallvec_inline![x]).collect(),
      &SrcPrefix(prefix, 0) => prefix_stmt("saddr", prefix).into_iter().map(|x| smallvec_inline![x]).collect(),
      &DstPrefix(pattern, offset) => pattern_stmt(false, pattern, offset).into_iter().collect(),
      &SrcPrefix(pattern, offset) => pattern_stmt(true, pattern, offset).into_iter().collect(),

      Protocol(ops) => match tp_code {
        Some(code) => ops.op(code).then(SmallVec::new_const).ok_or(Error::MatchNothing)?,
        None => range_stmt_branch(make_meta(expr::MetaKey::L4proto), ops, 0xff)?,
      },

      Port(ops) => {
        let th = th?;
        range_stmt(make_payload_field(th, "dport"), ops, 0xffff)?
          .into_iter()
          .chain(range_stmt(make_payload_field(th, "sport"), ops, 0xffff)?)
          .map(|x| smallvec_inline![x])
          .collect()
      }
      DstPort(ops) => range_stmt_branch(make_payload_field(th?, "dport"), ops, 0xffff)?,
      SrcPort(ops) => range_stmt_branch(make_payload_field(th?, "sport"), ops, 0xffff)?,
      IcmpType(ops) if tp == Icmp => range_stmt_branch(make_payload_field(icmp, "type"), ops, 0xff)?,
      IcmpCode(ops) if tp == Icmp => range_stmt_branch(make_payload_field(icmp, "code"), ops, 0xff)?,
      IcmpType(_) | IcmpCode(_) => return Err(Error::MatchNothing),
      TcpFlags(ops) => {
        let tt = ops.to_truth_table();
        let tt = tt.shrink(0b11111111);
        if tt.is_always_false() {
          return Err(Error::MatchNothing);
        } else if tt.is_always_true() {
          return Ok(SmallVec::new_const());
        }
        smallvec_inline![smallvec_inline![make_match(
          if tt.inv {
            stmt::Operator::NEQ
          } else {
            stmt::Operator::EQ
          },
          expr::Expression::BinaryOperation(Box::new(expr::BinaryOperation::AND(
            make_payload_field("tcp", "flags"),
            Number(tt.mask as u32),
          ))),
          expr::Expression::Named(expr::NamedExpression::Set(
            (tt.truth.iter().copied())
              .map(|x| expr::SetItem::Element(Number(x as u32)))
              .collect(),
          )),
        )]]
      }
      PacketLen(ops) => {
        let ops = if afi == Afi::Ipv4 {
          Cow::Borrowed(ops)
        } else {
          Cow::Owned(ops.with_offset(-40))
        };
        range_stmt_branch(make_payload_field(ip_ver, "length"), &ops, 0xffff)?
      }
      Dscp(ops) => range_stmt_branch(make_payload_field(ip_ver, "dscp"), ops, 0x3f)?,
      Fragment(ops) => {
        // int frag_op_value = [LF,FF,IsF,DF]
        // possible: [DF], [IsF], [FF], [LF], [LF,IsF](=[LF])
        let mask = if afi == Afi::Ipv4 { 0b1111 } else { 0b1110 };
        let tt = ops.to_truth_table();
        let tt = tt.shrink(mask);
        let valid_set = [0b0001, 0b0010, 0b1010, 0b0100, 0b1000].into_iter().collect();
        let mut new_set: BTreeSet<_> = tt.possible_values_masked().intersection(&valid_set).copied().collect();
        new_set.remove(&0b1010).then(|| new_set.insert(0b1000));

        let mut iter = new_set.into_iter().peekable();
        let mut branch = StatementBranch::new();

        let frag_off = if afi == Afi::Ipv4 {
          make_payload_field("ip", "frag-off")
        } else {
          make_exthdr("frag", "frag-off", 0)
        };
        let mf = if afi == Afi::Ipv4 {
          make_payload_raw(expr::PayloadBase::NH, 18, 1)
        } else {
          make_exthdr("frag", "more-fragments", 0)
        };

        // DF (IPv4)
        if let Some(0b0001) = iter.peek() {
          iter.next();
          branch.push(smallvec_inline![make_match(
            stmt::Operator::EQ,
            make_payload_raw(expr::PayloadBase::NH, 17, 1),
            Number(1),
          )]);
        }
        // IsF: {ip,frag} frag-off != 0
        if let Some(0b0010) = iter.peek() {
          iter.next();
          branch.push(smallvec_inline![make_match(
            stmt::Operator::NEQ,
            frag_off.clone(),
            Number(0)
          )]);
        }
        // FF: {ip,frag} frag-off == 0 && MF == 1
        if let Some(0b0100) = iter.peek() {
          iter.next();
          branch.push(smallvec![
            make_match(stmt::Operator::EQ, frag_off.clone(), Number(0)),
            make_match(stmt::Operator::EQ, mf.clone(), Number(1)),
          ]);
        }
        // LF: {ip,frag} frag-off != 0 && MF == 0
        if let Some(0b1000) = iter.peek() {
          iter.next();
          branch.push(smallvec![
            make_match(stmt::Operator::NEQ, frag_off, Number(0)),
            make_match(stmt::Operator::EQ, mf, Number(0)),
          ]);
        }
        branch
      }
      FlowLabel(ops) => range_stmt_branch(make_payload_field("ip6", "flowlabel"), ops, 0x1fff)?,
    };
    Ok(result)
  }
}

impl RouteInfo<'_> {
  pub(super) fn to_nft_stmts(
    &self,
    afi: Afi,
    prefix: IpPrefix,
    rtnl: &mut Option<RtNetlink<Linux>>,
    rtnl_args: &RtNetlinkArgs,
  ) -> Option<(StatementBranch<'static>, Option<(IpAddr, u32)>)> {
    let set = (self.ext_comm.iter().copied())
      .filter_map(ExtCommunity::action)
      .chain(self.ipv6_ext_comm.iter().copied().filter_map(Ipv6ExtCommunity::action))
      .map(|x| (x.kind(), x))
      .collect::<BTreeMap<_, _>>();
    let mut terminal = set
      .get(&TrafficFilterActionKind::TrafficAction)
      .map(|x| {
        let &TrafficFilterAction::TrafficAction { terminal, .. } = x else {
          unreachable!()
        };
        terminal
      })
      .unwrap_or(true);
    let mut last_term = false;
    let mut rt_info = None;
    let mut result = set
      .into_values()
      .map(move |x| x.to_nft_stmts(afi, prefix, rtnl, rtnl_args))
      .map(|(x, r, term)| {
        term.then(|| terminal = false);
        rt_info = r;
        (x, replace(&mut last_term, term))
      })
      .map_while(|(x, term)| term.not().then_some(x))
      .filter(|x| !x.is_empty())
      .collect::<StatementBranch>();
    if terminal {
      let ll = result.last().and_then(|x| x.last());
      if ll.is_some_and(|x| *x == ACCEPT || *x == DROP) || ll.is_none() {
        result.push(smallvec_inline![ACCEPT]);
      } else {
        result.last_mut().unwrap().push(ACCEPT);
      }
    }
    result.is_empty().not().then_some((result, rt_info))
  }
}

impl TrafficFilterAction {
  fn to_nft_stmts(
    self,
    afi: Afi,
    prefix: IpPrefix,
    rtnl: &mut Option<RtNetlink<Linux>>,
    rtnl_args: &RtNetlinkArgs,
  ) -> (StatementBlock<'static>, Option<(IpAddr, u32)>, bool) {
    use TrafficFilterAction::*;
    let action = match self {
      TrafficRateBytes { rate, .. } | TrafficRatePackets { rate, .. } if rate <= 0. || rate.is_nan() => {
        return (smallvec_inline![DROP], None, true);
      }
      TrafficRateBytes { rate, .. } => smallvec![make_limit(true, rate, "bytes", "second"), DROP],
      TrafficRatePackets { rate, .. } => smallvec![make_limit(true, rate, "packets", "second"), DROP],
      TrafficAction { sample: true, .. } => smallvec_inline![stmt::Statement::Log(Some(stmt::Log::new(None))),],
      TrafficAction { .. } => SmallVec::new_const(),
      RtRedirect { .. } | RtRedirectIpv6 { .. } => SmallVec::new_const(), // redirect is not supported at the moment
      TrafficMarking { dscp } => smallvec_inline![mangle_stmt(
        make_payload_field(if afi == Afi::Ipv4 { "ip" } else { "ip6" }, "dscp"),
        Number(dscp.into())
      )],
      RedirectToIp { ip, copy: true } => smallvec_inline![stmt::Statement::Dup(stmt::Dup {
        addr: Str(ip.to_string().into()),
        dev: None,
      })],
      RedirectToIp { ip, copy: false } => {
        let rtnl = if let Some(rtnl) = rtnl {
          rtnl
        } else {
          let new = RtNetlink::new(rtnl_args.clone()).unwrap();
          rtnl.get_or_insert(new)
        };
        let table_id = rtnl.next_table_for(prefix);
        let result = smallvec_inline![mangle_stmt(make_meta(expr::MetaKey::Mark), Number(table_id))];
        return (result, Some((ip, table_id)), false);
      }
    };
    (action, None, false)
  }
}

pub(crate) const ACCEPT: stmt::Statement = stmt::Statement::Accept(None);
pub(crate) const DROP: stmt::Statement = stmt::Statement::Drop(None);

pub(crate) fn make_match<'a>(
  op: stmt::Operator,
  left: expr::Expression<'a>,
  right: expr::Expression<'a>,
) -> stmt::Statement<'a> {
  stmt::Statement::Match(stmt::Match { left, right, op })
}

pub(crate) fn make_limit<'a>(over: bool, rate: f32, unit: &'a str, per: &'a str) -> stmt::Statement<'a> {
  stmt::Statement::Limit(stmt::Limit {
    rate: rate.round() as u32,
    rate_unit: Some(unit.into()),
    per: Some(per.into()),
    burst: Some(0),
    burst_unit: Some("bytes".into()),
    inv: Some(over),
  })
}

pub(crate) fn make_payload_raw(base: expr::PayloadBase, offset: u32, len: u32) -> expr::Expression<'static> {
  expr::Expression::Named(expr::NamedExpression::Payload(expr::Payload::PayloadRaw(
    expr::PayloadRaw { base, offset, len },
  )))
}

pub(crate) fn make_payload_field<'a>(protocol: &'a str, field: &'a str) -> expr::Expression<'a> {
  expr::Expression::Named(expr::NamedExpression::Payload(expr::Payload::PayloadField(
    expr::PayloadField { protocol: protocol.into(), field: field.into() },
  )))
}

pub(crate) fn make_meta(key: expr::MetaKey) -> expr::Expression<'static> {
  expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta { key }))
}

pub(crate) fn make_exthdr<'a>(name: &'a str, field: &'a str, offset: u32) -> expr::Expression<'a> {
  expr::Expression::Named(expr::NamedExpression::Exthdr(expr::Exthdr {
    name: name.into(),
    field: Some(field.into()),
    offset: Some(offset),
  }))
}

pub(crate) fn prefix_stmt(field: &'static str, prefix: IpPrefix) -> Option<stmt::Statement<'static>> {
  (prefix.len() != 0).then(|| {
    make_match(
      stmt::Operator::EQ,
      make_payload_field(if prefix.afi() == Afi::Ipv4 { "ip" } else { "ip6" }, field),
      if prefix.is_single() {
        Str(format!("{}", prefix.prefix()).into())
      } else {
        expr::Expression::Named(expr::NamedExpression::Prefix(expr::Prefix {
          addr: Box::new(Str(format!("{}", prefix.prefix()).into())),
          len: prefix.len().into(),
        }))
      },
    )
  })
}

pub(crate) fn pattern_stmt(src: bool, pattern: IpPrefix, offset: u8) -> Option<StatementBlock<'static>> {
  if pattern.len() == 0 {
    return None;
  }

  let mut buf = SmallVec::new_const();

  buf.push(make_match(
    stmt::Operator::EQ,
    make_meta(expr::MetaKey::Nfproto),
    Str("ipv6".into()),
  ));

  let addr_offset = if src { 64 } else { 192 };
  let start_32bit = offset.next_multiple_of(32);
  let pre_rem = start_32bit - offset;
  let end_32bit = pattern.len().prev_multiple_of(&32); // this uses num::Integer, not std
  let post_rem = pattern.len() - end_32bit;

  let IpAddr::V6(ip) = pattern.prefix() else {
    unreachable!();
  };
  if start_32bit + 32 <= end_32bit {
    if pre_rem > 0 {
      let num = ip.to_bits() >> (128 - start_32bit);
      buf.push(make_match(
        stmt::Operator::EQ,
        make_payload_raw(expr::PayloadBase::NH, addr_offset + offset as u32, pre_rem.into()),
        Number(num.try_into().unwrap()),
      ));
    }
    for i in (start_32bit..end_32bit).step_by(32) {
      let num = (ip.to_bits() >> (pattern.len() - 8 - i)) as u32;
      buf.push(make_match(
        stmt::Operator::EQ,
        make_payload_raw(expr::PayloadBase::NH, addr_offset + i as u32, 32),
        Number(num),
      ));
    }
    if post_rem > 0 {
      let num = ((ip.to_bits() >> (128 - pattern.len())) as u32) & (u32::MAX >> (32 - post_rem));
      buf.push(make_match(
        stmt::Operator::EQ,
        make_payload_raw(expr::PayloadBase::NH, addr_offset + end_32bit as u32, post_rem.into()),
        Number(num),
      ));
    }
  } else {
    let num = ip.to_bits() >> (128 - pattern.len());
    buf.push(make_match(
      stmt::Operator::EQ,
      make_payload_raw(
        expr::PayloadBase::NH,
        addr_offset + u32::from(offset),
        u32::from(pattern.len() - offset),
      ),
      Number(num.try_into().unwrap()),
    ));
  }

  Some(buf)
}

pub(crate) fn range_stmt<'a>(
  left: expr::Expression<'a>,
  ops: &Ops<Numeric>,
  max: u64,
) -> Result<Option<stmt::Statement<'a>>> {
  let ranges = ops.to_ranges();
  if is_sorted_ranges_always_true(&ranges) {
    return Ok(None);
  } else if ranges.is_empty() {
    return Err(Error::MatchNothing);
  }
  let right = if ranges.len() == 1 {
    let (start, end) = ranges.into_iter().next().unwrap().into_inner();
    if start == end {
      Number(start as u32)
    } else {
      expr::Expression::Range(Box::new(expr::Range {
        range: [Number(start as u32), Number(min(end, max) as u32)],
      }))
    }
  } else {
    let allowed = ranges
      .into_iter()
      .map(RangeInclusive::into_inner)
      .filter_map(|(a, b)| (a <= max).then_some(if b <= max { a..=b } else { a..=max }))
      .map(|x| {
        let (start, end) = x.into_inner();
        // HACK: Does nftables itself support 64-bit integers? We shrink it for now.
        // But most of the matching expressions is smaller than 32 bits anyway.
        let expr = if start == end {
          Number(start as u32)
        } else {
          expr::Expression::Range(Box::new(expr::Range {
            range: [Number(start as u32), Number(end as u32)],
          }))
        };
        expr::SetItem::Element(expr)
      })
      .collect();
    expr::Expression::Named(expr::NamedExpression::Set(allowed))
  };
  Ok(Some(make_match(stmt::Operator::EQ, left, right)))
}

pub(crate) fn range_stmt_branch<'a>(
  left: expr::Expression<'a>,
  ops: &Ops<Numeric>,
  max: u64,
) -> Result<StatementBranch<'a>> {
  range_stmt(left, ops, max).map(|x| x.into_iter().map(|x| smallvec_inline![x]).collect())
}

pub(crate) fn mangle_stmt<'a>(key: expr::Expression<'a>, value: expr::Expression<'a>) -> stmt::Statement<'a> {
  stmt::Statement::Mangle(stmt::Mangle { key, value })
}

impl Ops<Numeric> {
  fn to_ranges(&self) -> Vec<RangeInclusive<u64>> {
    let mut buf = Vec::new();
    let mut cur = SmallVec::<[_; 4]>::new();
    cur.extend(self.0[0].to_range_iter());

    for op in &self.0[1..] {
      if op.is_and() {
        if cur.is_empty() {
          continue;
        }
        let Some((r1, r2)) = op.to_ranges() else {
          cur.clear();
          continue;
        };

        let mut addition = SmallVec::<[_; 4]>::new();
        cur.retain(|x| {
          if let Some(y) = x.clone().intersect(r1.clone()) {
            if let Some(r2) = &r2 {
              addition.extend(x.clone().intersect(r2.clone()));
            }
            *x = y;
            return true;
          } else if let Some(r2) = &r2
            && let Some(y) = x.clone().intersect(r2.clone())
          {
            *x = y;
            return true;
          }
          false
        });
        cur.extend(addition);
      } else {
        buf.extend(cur.drain(..));
        cur.extend(op.to_range_iter());
      }
    }
    buf.extend(cur);
    buf.sort_unstable_by_key(|x| x.clone().into_inner());
    buf
  }

  pub fn offset(&mut self, offset: i64) {
    self.0.iter_mut().for_each(|x| *x = x.offset(offset));
  }

  pub fn with_offset(&self, offset: i64) -> Self {
    let mut ops = self.clone();
    ops.offset(offset);
    ops
  }
}

impl Ops<Bitmask> {
  fn to_truth_table(&self) -> TruthTable {
    let mut buf = TruthTable::always_false();
    let mut cur = self.0[0].to_truth_table();

    for op in &self.0[1..] {
      if op.is_and() {
        if cur.is_always_false() {
          continue;
        }
        cur = cur.and(op.to_truth_table());
      } else {
        buf = buf.or(cur);
        cur = op.to_truth_table();
      }
    }
    buf = buf.or(cur);
    buf
  }
}

impl Op<Numeric> {
  fn to_ranges(self) -> Option<(RangeInclusive<u64>, Option<RangeInclusive<u64>>)> {
    use NumericFlags::*;
    match NumericFlags::from_repr(self.flags & 0b111).unwrap() {
      False => None,
      Lt if self.value == 0 => None,
      Gt if self.value == u64::MAX => None,
      Lt => Some((0..=self.value - 1, None)),
      Gt => Some((self.value + 1..=u64::MAX, None)),
      Eq => Some((self.value..=self.value, None)),
      Le => Some((0..=self.value, None)),
      Ge => Some((self.value..=u64::MAX, None)),
      Ne => Some((0..=self.value - 1, Some(self.value + 1..=u64::MAX))),
      True => Some((0..=u64::MAX, None)),
    }
  }

  fn to_range_iter(self) -> impl Iterator<Item = RangeInclusive<u64>> + Clone {
    self
      .to_ranges()
      .map(|(a, b)| [Some(a), b].into_iter().flatten())
      .into_iter()
      .flatten()
  }

  /// Offset the operator by adding n (no overflow) to every value compared.
  fn offset(self, n: i64) -> Self {
    use NumericFlags::*;
    use Ordering::*;

    let diff = n.unsigned_abs();
    let f = NumericFlags::from_repr(self.flags & 0b111).unwrap();

    let (flags, value) = match (f, n.cmp(&0)) {
      (_, Equal) => return self,
      (False | True, _) => (f, 0),
      (Lt | Le | Eq | Ne, Less) => self.value.checked_sub(diff).map(|v| (f, v)).unwrap_or((False, 0)),
      (Lt | Le, Greater) => self.value.checked_add(diff).map(|v| (f, v)).unwrap_or((True, 0)),
      (Gt | Ge | Eq | Ne, Greater) => self.value.checked_add(diff).map(|v| (f, v)).unwrap_or((False, 0)),
      (Gt | Ge, Less) => self.value.checked_sub(diff).map(|v| (f, v)).unwrap_or((True, 0)),
    };

    let flags = self.flags & Self::AND | flags as u8;
    Self { flags, value, _k: PhantomData }
  }
}

impl Op<Bitmask> {
  pub fn to_truth_table(self) -> TruthTable {
    use BitmaskFlags::*;
    let (inv, init) = match (BitmaskFlags::from_repr(self.flags & 0b11).unwrap(), self.value) {
      (Any | NotAll, 0) => (false, None), // always false
      (NotAny | All, 0) => (true, None),  // always true
      (Any, _) => (true, Some(0)),
      (NotAny, _) => (false, Some(0)),
      (All, _) => (false, Some(self.value)),
      (NotAll, _) => (true, Some(self.value)),
    };
    let mut truth = BTreeSet::new();
    truth.extend(init);
    TruthTable { mask: self.value, inv, truth }
  }
}

/// This assumes the ranges are sorted as (range.start, range.end).
fn is_sorted_ranges_always_true<'a>(ranges: impl IntoIterator<Item = &'a RangeInclusive<u64>>) -> bool {
  let mut iter = ranges.into_iter();
  let Some(mut buf) = iter.next().cloned() else {
    return false;
  };
  for r in iter {
    if buf.end() >= r.start() {
      buf = *buf.start()..=*r.end();
    } else {
      return false;
    }
  }
  buf == (0..=u64::MAX)
}

#[cfg(test)]
mod tests {
  use super::*;
  use test_case::test_case;

  #[test_case(&[0x03, 114, 0x54, 2, 2, 0x81, 1], &[1..=1, 114..=513])]
  #[test_case(&[0x06, 114, 0x56, 2, 2, 0xd6, 7, 127], &[0..=113, 115..=513, 515..=1918, 1920..=u64::MAX])]
  #[tokio::test]
  async fn test_ops_to_range(mut seq: &[u8], result: &[RangeInclusive<u64>]) -> anyhow::Result<()> {
    let ops = Ops::<Numeric>::read(&mut seq).await?;
    let ranges = ops.to_ranges();
    println!("{ranges:?}");
    assert_eq!(ranges, result);
    Ok(())
  }
}
