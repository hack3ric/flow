use crate::bgp::flow::{Bitmask, BitmaskFlags, Component, ComponentKind, Flowspec, Numeric, NumericFlags, Op, Ops};
use crate::bgp::route::{ExtCommunity, Ipv6ExtCommunity, RouteInfo, TrafficFilterAction, TrafficFilterActionKind};
use crate::net::{Afi, IpPrefix};
use crate::util::Intersect;
use nftables::batch::Batch;
use nftables::expr::Expression::{Number as NUM, String as STRING};
use nftables::helper::{apply_ruleset, get_current_ruleset_raw, NftablesError};
use nftables::{expr, schema, stmt, types};
use num::Integer;
use serde::{Deserialize, Serialize};
use smallvec::{smallvec, smallvec_inline, SmallVec};
use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter, Write};
use std::marker::PhantomData;
use std::mem::replace;
use std::net::IpAddr;
use std::ops::{Add, Not, RangeInclusive};
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize)]
pub struct Nft {
  table: Cow<'static, str>,
  chain: Cow<'static, str>,
  #[serde(skip)]
  armed: bool,
}

impl Nft {
  pub fn new() -> Result<Self, NftablesError> {
    Self::with_names("flowspecs", "flowspecs")
  }

  pub fn with_names(
    table: impl Into<Cow<'static, str>>,
    chain: impl Into<Cow<'static, str>>,
  ) -> Result<Self, NftablesError> {
    let table = table.into();
    let chain = chain.into();
    let mut batch = Batch::new();
    batch.add(schema::NfListObject::Table(schema::Table {
      family: types::NfFamily::INet,
      name: table.to_string(),
      ..Default::default()
    }));
    batch.add(schema::NfListObject::Chain(schema::Chain {
      family: types::NfFamily::INet,
      table: table.to_string(),
      name: chain.to_string(),
      ..Default::default()
    }));
    apply_ruleset(&batch.to_nftables(), None, None)?;
    Ok(Self { table, chain, armed: true })
  }

  fn exit(&self) -> Result<(), NftablesError> {
    let mut batch = Batch::new();
    batch.delete(schema::NfListObject::Table(schema::Table {
      family: types::NfFamily::INet,
      name: self.table.to_string(),
      ..Default::default()
    }));
    apply_ruleset(&batch.to_nftables(), None, None)
  }

  pub fn make_new_rule(&self, stmts: Vec<stmt::Statement>, comment: Option<impl ToString>) -> schema::NfListObject {
    schema::NfListObject::Rule(schema::Rule {
      family: types::NfFamily::INet,
      table: self.table.to_string(),
      chain: self.chain.to_string(),
      expr: stmts,
      comment: comment.map(|x| x.to_string()),
      ..Default::default()
    })
  }

  pub fn make_rule_handle(&self, handle: u32) -> schema::NfListObject {
    schema::NfListObject::Rule(schema::Rule {
      family: types::NfFamily::INet,
      table: self.table.to_string(),
      chain: self.chain.to_string(),
      handle: Some(handle),
      ..Default::default()
    })
  }

  pub fn get_current_ruleset_raw(&self) -> Result<String, NftablesError> {
    let args = vec!["-n", "-s", "list", "chain", "inet", &self.table, &self.chain];
    get_current_ruleset_raw(None, Some(args))
  }

  pub fn apply_ruleset(&self, batch: Batch) -> Result<(), NftablesError> {
    apply_ruleset(&batch.to_nftables(), None, None)
  }
}

impl Drop for Nft {
  fn drop(&mut self) {
    if self.armed {
      let _ = self.exit();
    }
  }
}

pub fn flow_to_nft_stmts(
  spec: &Flowspec,
  info: &RouteInfo,
) -> Result<impl Iterator<Item = Vec<stmt::Statement>>, ToNftStmtError> {
  let mut total = 1usize;
  let base = spec
    .to_nft_stmts()?
    .chain(info.to_nft_stmts(spec.afi()).map(Ok))
    .map(|result| {
      result.map(|branch| {
        let count = total;
        total *= branch.len();
        (branch, count)
      })
    })
    .collect::<Result<Vec<_>, _>>()?;
  let result = (0..total).map(move |i| {
    (base.iter())
      .map(|(x, v)| x[(x.len() == 1).then_some(0).unwrap_or_else(|| i / v % x.len())].iter())
      .flatten()
      .cloned()
      .collect::<Vec<_>>()
  });
  Ok(result)
}

/// Makes sure transport protocol is consistent across components inside a
/// flowspec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
  Tcp,
  Icmp,
  Unknown,
}

type StatementBlock = SmallVec<[stmt::Statement; 1]>;
type StatementBranch = SmallVec<[StatementBlock; 1]>;

impl Flowspec {
  fn to_nft_stmts(&self) -> Result<impl Iterator<Item = Result<StatementBranch, ToNftStmtError>> + '_, ToNftStmtError> {
    use ComponentKind as CK;

    let set = self.component_set();
    let tcp = set.contains(&CK::TcpFlags);
    let icmp = set.contains(&CK::IcmpType) || set.contains(&CK::IcmpCode);
    let transport = match (tcp, icmp) {
      (false, false) => Transport::Unknown,
      (false, true) => Transport::Icmp,
      (true, false) => Transport::Tcp,
      _ => return Err(ToNftStmtError(())),
    };

    let first = make_match(
      stmt::Operator::EQ,
      make_meta(expr::MetaKey::Nfproto),
      STRING((self.afi() == Afi::Ipv4).then_some("ipv4").unwrap_or("ipv6").into()),
    );
    let result = Some(Ok(smallvec_inline![smallvec_inline![first]]))
      .into_iter()
      .chain(self.components().map(move |x| x.to_nft_stmts(self.afi(), transport)))
      .filter(|x| x.is_err() || x.as_ref().is_ok_and(|y| !y.is_empty()));
    Ok(result)
  }
}

impl Component {
  fn to_nft_stmts(&self, afi: Afi, tp: Transport) -> Result<StatementBranch, ToNftStmtError> {
    // TODO: simple case optimization
    use Component::*;
    use Transport::*;

    let ip_ver = (afi == Afi::Ipv4).then_some("ip").unwrap_or("ip6");
    let icmp = (afi == Afi::Ipv4).then_some("icmp").unwrap_or("icmpv6");
    let (th, tp_code) = match tp {
      Tcp => (Ok("tcp"), Some(6)),
      Icmp => (
        Err(ToNftStmtError(())),
        Some((afi == Afi::Ipv4).then_some(1).unwrap_or(58)),
      ),
      Unknown => (Ok("th"), None),
    };
    let result: StatementBranch = match self {
      &DstPrefix(prefix, 0) => prefix_stmt("daddr", prefix).into_iter().map(|x| smallvec_inline![x]).collect(),
      &SrcPrefix(prefix, 0) => prefix_stmt("saddr", prefix).into_iter().map(|x| smallvec_inline![x]).collect(),
      &DstPrefix(pattern, offset) => pattern_stmt(false, pattern, offset).into_iter().collect(),
      &SrcPrefix(pattern, offset) => pattern_stmt(true, pattern, offset).into_iter().collect(),

      Protocol(ops) => match tp_code {
        Some(code) => ops.op(code).then(SmallVec::new_const).ok_or(ToNftStmtError(()))?,
        None => range_stmt_branch(make_meta(expr::MetaKey::L4proto), ops, 0xff)?,
      },

      Port(ops) => range_stmt(make_payload_field(th?, "dport"), ops, 0xffff)?
        .into_iter()
        .chain(range_stmt(make_payload_field(th?, "sport"), ops, 0xffff)?)
        .map(|x| smallvec_inline![x])
        .collect(),
      DstPort(ops) => range_stmt_branch(make_payload_field(th?, "dport"), ops, 0xffff)?,
      SrcPort(ops) => range_stmt_branch(make_payload_field(th?, "sport"), ops, 0xffff)?,
      IcmpType(ops) if tp == Icmp => range_stmt_branch(make_payload_field(icmp, "type"), ops, 0xff)?,
      IcmpCode(ops) if tp == Icmp => range_stmt_branch(make_payload_field(icmp, "code"), ops, 0xff)?,
      IcmpType(_) | IcmpCode(_) => return Err(ToNftStmtError(())),
      TcpFlags(ops) => {
        // TODO: simple case: one single bit op
        let tt = ops.to_truth_table();
        let tt = tt.shrink(0b11111111);
        if tt.is_always_false() {
          return Err(ToNftStmtError(()));
        } else if tt.is_always_true() {
          return Ok(SmallVec::new_const());
        }
        smallvec_inline![smallvec_inline![make_match(
          tt.inv.then_some(stmt::Operator::NEQ).unwrap_or(stmt::Operator::EQ),
          expr::Expression::BinaryOperation(expr::BinaryOperation::AND(
            Box::new(make_payload_field("tcp", "flags")),
            Box::new(NUM(tt.mask as u32)),
          )),
          expr::Expression::Named(expr::NamedExpression::Set(
            (tt.truth.iter().copied())
              .map(|x| expr::SetItem::Element(NUM(x as u32)))
              .collect(),
          )),
        )]]
      }
      PacketLen(ops) => {
        let ops = (afi == Afi::Ipv4)
          .then(|| Cow::Borrowed(ops))
          .unwrap_or_else(|| Cow::Owned(ops.with_offset(-40)));
        range_stmt_branch(make_payload_field(ip_ver, "length"), &ops, 0xffff)?
      }
      Dscp(ops) => range_stmt_branch(make_payload_field(ip_ver, "dscp"), ops, 0x3f)?,
      Fragment(ops) => {
        // TODO: reduce clone
        // int frag_op_value = [LF,FF,IsF,DF]
        // possible: [DF], [IsF], [FF], [LF], [LF,IsF](=[LF])
        let mask = (afi == Afi::Ipv4).then_some(0b1111).unwrap_or(0b1110);
        let tt = ops.to_truth_table();
        let tt = tt.shrink(mask);
        let valid_set = [0b0001, 0b0010, 0b1010, 0b0100, 0b1000].into_iter().collect();
        let mut new_set: BTreeSet<_> = tt.possible_values_masked().intersection(&valid_set).copied().collect();
        new_set.remove(&0b1010).then(|| new_set.insert(0b1000));

        let mut iter = new_set.into_iter().peekable();
        let mut branch = StatementBranch::new();

        let frag_off = (afi == Afi::Ipv4)
          .then(|| make_payload_field("ip", "frag-off"))
          .unwrap_or_else(|| make_exthdr("frag", "frag-off", 0));
        let mf = (afi == Afi::Ipv4)
          .then(|| make_payload_raw(expr::PayloadBase::NH, 18, 1))
          .unwrap_or_else(|| make_exthdr("frag", "more-fragments", 0));

        // DF (IPv4)
        if let Some(0b0001) = iter.peek() {
          iter.next();
          branch.push(smallvec_inline![make_match(
            stmt::Operator::EQ,
            make_payload_raw(expr::PayloadBase::NH, 17, 1),
            NUM(1),
          )]);
        }
        // IsF: {ip,frag} frag-off != 0
        if let Some(0b0010) = iter.peek() {
          iter.next();
          branch.push(smallvec_inline![make_match(
            stmt::Operator::NEQ,
            frag_off.clone(),
            NUM(0)
          )]);
        }
        // FF: {ip,frag} frag-off == 0 && MF == 1
        if let Some(0b0100) = iter.peek() {
          iter.next();
          branch.push(smallvec![
            make_match(stmt::Operator::EQ, frag_off.clone(), NUM(0)),
            make_match(stmt::Operator::EQ, mf.clone(), NUM(1)),
          ]);
        }
        // LF: {ip,frag} frag-off != 0 && MF == 0
        if let Some(0b1000) = iter.peek() {
          iter.next();
          branch.push(smallvec![
            make_match(stmt::Operator::NEQ, frag_off, NUM(0)),
            make_match(stmt::Operator::EQ, mf, NUM(0)),
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
  fn to_nft_stmts(&self, afi: Afi) -> Option<StatementBranch> {
    let set = (self.ext_comm.iter().copied())
      .filter_map(ExtCommunity::action)
      .chain(self.ipv6_ext_comm.iter().copied().filter_map(Ipv6ExtCommunity::action))
      .map(|x| (x.kind(), x))
      .collect::<BTreeMap<_, _>>();
    let extract_terminal = |x| {
      let &TrafficFilterAction::TrafficAction { terminal, .. } = x else {
        unreachable!()
      };
      terminal
    };
    let mut terminal = set
      .get(&TrafficFilterActionKind::TrafficAction)
      .map(extract_terminal)
      .unwrap_or(true);
    let mut last_term = false;
    let mut result = set
      .into_values()
      .map(move |x| x.to_nft_stmts(afi))
      .map(|(x, term)| (x, replace(&mut last_term, term.then(|| terminal = false).is_some())))
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
    result.is_empty().not().then_some(result)
  }
}

impl TrafficFilterAction {
  fn to_nft_stmts(self, afi: Afi) -> (StatementBlock, bool) {
    use TrafficFilterAction::*;
    let action = match self {
      TrafficRateBytes { rate, .. } | TrafficRatePackets { rate, .. } if rate <= 0. || rate.is_nan() => {
        return (smallvec_inline![DROP], true)
      }
      TrafficRateBytes { rate, .. } => smallvec![make_limit(true, rate, "bytes", "second"), DROP],
      TrafficRatePackets { rate, .. } => smallvec![make_limit(true, rate, "packets", "second"), DROP],
      TrafficAction { sample: true, .. } => smallvec_inline![stmt::Statement::Log(Some(stmt::Log::new(None))),],
      TrafficAction { .. } => SmallVec::new_const(),
      RtRedirect { .. } | RtRedirectIpv6 { .. } => todo!("redirect is not supported at the moment"),
      TrafficMarking { dscp } => smallvec_inline![stmt::Statement::Mangle(stmt::Mangle {
        key: make_payload_field((afi == Afi::Ipv4).then_some("ip").unwrap_or("ip6"), "dscp"),
        value: NUM(dscp.into()),
      })],
    };
    (action, false)
  }
}

const ACCEPT: stmt::Statement = stmt::Statement::Accept(Some(stmt::Accept {}));
const DROP: stmt::Statement = stmt::Statement::Drop(Some(stmt::Drop {}));

fn make_match(op: stmt::Operator, left: expr::Expression, right: expr::Expression) -> stmt::Statement {
  stmt::Statement::Match(stmt::Match { left, right, op })
}

fn make_limit(over: bool, rate: f32, unit: impl ToString, per: impl ToString) -> stmt::Statement {
  stmt::Statement::Limit(stmt::Limit {
    rate: rate.round() as u32,
    rate_unit: Some(unit.to_string()),
    per: Some(per.to_string()),
    burst: None,
    burst_unit: None,
    inv: Some(over),
  })
}

fn make_payload_raw(base: expr::PayloadBase, offset: u32, len: u32) -> expr::Expression {
  expr::Expression::Named(expr::NamedExpression::Payload(expr::Payload::PayloadRaw(
    expr::PayloadRaw { base, offset, len },
  )))
}

fn make_payload_field(protocol: impl ToString, field: impl ToString) -> expr::Expression {
  expr::Expression::Named(expr::NamedExpression::Payload(expr::Payload::PayloadField(
    expr::PayloadField { protocol: protocol.to_string(), field: field.to_string() },
  )))
}

fn make_meta(key: expr::MetaKey) -> expr::Expression {
  expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta { key }))
}

fn make_exthdr(name: impl ToString, field: impl ToString, offset: u32) -> expr::Expression {
  expr::Expression::Named(expr::NamedExpression::Exthdr(expr::Exthdr {
    name: name.to_string(),
    field: field.to_string(),
    offset,
  }))
}

fn prefix_stmt(field: impl ToString, prefix: IpPrefix) -> Option<stmt::Statement> {
  (prefix.len() != 0).then(|| {
    make_match(
      stmt::Operator::EQ,
      make_payload_field(if prefix.afi() == Afi::Ipv4 { "ip" } else { "ip6" }, field),
      expr::Expression::Named(expr::NamedExpression::Prefix(expr::Prefix {
        addr: Box::new(STRING(format!("{}", prefix.prefix()))),
        len: prefix.len().into(),
      })),
    )
  })
}

fn pattern_stmt(src: bool, pattern: IpPrefix, offset: u8) -> Option<StatementBlock> {
  if pattern.len() == 0 {
    return None;
  }

  let mut buf = SmallVec::new_const();

  buf.push(make_match(
    stmt::Operator::EQ,
    make_meta(expr::MetaKey::Nfproto),
    STRING("ipv6".into()),
  ));

  let addr_offset = src.then_some(192).unwrap_or(64);
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
        NUM(num.try_into().unwrap()),
      ));
    }
    for i in (start_32bit..end_32bit).step_by(32) {
      let num = (ip.to_bits() >> (pattern.len() - 8 - i)) as u32;
      buf.push(make_match(
        stmt::Operator::EQ,
        make_payload_raw(expr::PayloadBase::NH, addr_offset + i as u32, 32),
        NUM(num),
      ));
    }
    if post_rem > 0 {
      let num = ((ip.to_bits() >> (128 - pattern.len())) as u32) & (u32::MAX >> (32 - post_rem));
      buf.push(make_match(
        stmt::Operator::EQ,
        make_payload_raw(expr::PayloadBase::NH, addr_offset + end_32bit as u32, post_rem.into()),
        NUM(num),
      ));
    }
  } else {
    let num = ip.to_bits() >> (128 - offset);
    buf.push(make_match(
      stmt::Operator::EQ,
      make_payload_raw(
        expr::PayloadBase::NH,
        addr_offset + u32::from(offset),
        u32::from(pattern.len() - offset),
      ),
      NUM(num.try_into().unwrap()),
    ));
  }

  Some(buf)
}

fn range_stmt(left: expr::Expression, ops: &Ops<Numeric>, max: u64) -> Result<Option<stmt::Statement>, ToNftStmtError> {
  let ranges = ops.to_ranges();
  if is_sorted_ranges_always_true(&ranges) {
    return Ok(None);
  } else if ranges.is_empty() {
    return Err(ToNftStmtError(()));
  }
  let allowed = ranges
    .into_iter()
    .map(RangeInclusive::into_inner)
    .filter_map(|(a, b)| (a <= max).then(|| (b <= max).then_some(a..=b).unwrap_or(a..=max)))
    .map(|x| {
      let (start, end) = x.into_inner();
      // HACK: Does nftables itself support 64-bit integers? We shrink it for now.
      // But most of the matching expressions is smaller than 32 bits anyway.
      let expr = (start == end)
        .then_some(NUM(start as u32))
        .unwrap_or_else(|| expr::Expression::Range(expr::Range { range: vec![NUM(start as u32), NUM(end as u32)] }));
      expr::SetItem::Element(expr)
    })
    .collect();
  Ok(Some(make_match(
    stmt::Operator::EQ,
    left,
    expr::Expression::Named(expr::NamedExpression::Set(allowed)),
  )))
}

fn range_stmt_branch(left: expr::Expression, ops: &Ops<Numeric>, max: u64) -> Result<StatementBranch, ToNftStmtError> {
  range_stmt(left, ops, max).map(|x| x.into_iter().map(|x| smallvec_inline![x]).collect())
}

#[derive(Debug, Clone, Copy, Error)]
#[error("flowspec matches nothing")]
pub struct ToNftStmtError(());

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
          } else if let Some(r2) = &r2 {
            if let Some(y) = x.clone().intersect(r2.clone()) {
              *x = y;
              return true;
            }
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

    // TODO: reduce clones
    for op in &self.0[1..] {
      if op.is_and() {
        if cur.is_always_false() {
          continue;
        }
        cur = cur.and(&op.to_truth_table()).into_owned();
      } else {
        buf = buf.or(&cur).into_owned();
        cur = op.to_truth_table();
      }
    }
    buf = buf.or(&cur).into_owned();
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
  fn to_truth_table(self) -> TruthTable {
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct TruthTable {
  mask: u64,
  inv: bool,
  truth: BTreeSet<u64>,
}

// TODO: reduce clone
impl TruthTable {
  pub fn always_true() -> Self {
    Self { mask: 0, inv: false, truth: BTreeSet::new() }
  }

  pub fn always_false() -> Self {
    Self { mask: 0, inv: false, truth: BTreeSet::new() }
  }

  pub fn is_always_true(&self) -> bool {
    self.inv && self.truth.is_empty() || !self.inv && self.truth.len() == 1 << self.mask.count_ones()
  }

  pub fn is_always_false(&self) -> bool {
    !self.inv && self.truth.is_empty() || self.inv && self.truth.len() == 1 << self.mask.count_ones()
  }

  pub fn and<'a>(&'a self, other: &'a Self) -> Cow<'a, Self> {
    if self.is_always_false() || other.is_always_false() {
      Cow::Owned(Self::always_false())
    } else if self.is_always_true() {
      Cow::Borrowed(other)
    } else if other.is_always_true() {
      Cow::Borrowed(self)
    } else {
      match (self.inv, other.inv) {
        (false, false) => Cow::Owned(self.truth_intersection(other, false)),
        (true, true) => Cow::Owned(self.truth_union(other, true)),
        (false, true) => Cow::Owned(self.truth_difference(other, false)),
        (true, false) => other.and(self),
      }
    }
  }

  pub fn or<'a>(&'a self, other: &'a Self) -> Cow<'a, Self> {
    if self.is_always_true() || other.is_always_true() {
      Cow::Owned(Self::always_true())
    } else if self.is_always_false() {
      Cow::Borrowed(other)
    } else if other.is_always_false() {
      Cow::Borrowed(self)
    } else {
      match (self.inv, other.inv) {
        (false, false) => Cow::Owned(self.truth_union(other, false)),
        (true, true) => Cow::Owned(self.truth_intersection(other, true)),
        (false, true) => Cow::Owned(other.truth_difference(self, true)),
        (true, false) => other.or(self),
      }
    }
  }

  #[allow(unused)]
  pub fn not(mut self) -> Self {
    self.inv = !self.inv;
    self
  }

  fn possible_values_masked(&self) -> Cow<BTreeSet<u64>> {
    if self.inv {
      Cow::Owned(
        iter_masked(self.mask)
          .collect::<BTreeSet<_>>()
          .difference(&self.truth)
          .copied()
          .collect(),
      )
    } else {
      Cow::Borrowed(&self.truth)
    }
  }

  pub fn shrink(&self, other_mask: u64) -> Cow<Self> {
    let mask = self.mask & other_mask;
    if mask == self.mask {
      Cow::Borrowed(self)
    } else {
      Cow::Owned(Self { mask, inv: self.inv, truth: self.truth.iter().map(|v| v & mask).collect() })
    }
  }

  pub fn expand(&self, other_mask: u64) -> Cow<Self> {
    let mask = self.mask | other_mask;
    if mask == self.mask {
      Cow::Borrowed(self)
    } else {
      Cow::Owned(Self {
        mask,
        inv: self.inv,
        truth: iter_masked(other_mask & !self.mask)
          .map(|a| self.truth.iter().map(move |b| a | b))
          .flatten()
          .collect(),
      })
    }
  }

  fn expand_set(&self, other_mask: u64) -> Cow<BTreeSet<u64>> {
    match self.expand(other_mask) {
      Cow::Borrowed(x) => Cow::Borrowed(&x.truth),
      Cow::Owned(x) => Cow::Owned(x.truth),
    }
  }

  fn truth_intersection(&self, other: &Self, inv: bool) -> Self {
    self.truth_op(other, inv, |a, b| a.intersection(b).copied().collect())
  }
  fn truth_union(&self, other: &Self, inv: bool) -> Self {
    self.truth_op(other, inv, |a, b| a.union(b).copied().collect())
  }
  fn truth_difference(&self, other: &Self, inv: bool) -> Self {
    self.truth_op(other, inv, |a, b| a.difference(b).copied().collect())
  }
  fn truth_op<F>(&self, other: &Self, inv: bool, f: F) -> Self
  where
    F: for<'a> FnOnce(&'a BTreeSet<u64>, &'a BTreeSet<u64>) -> BTreeSet<u64>,
  {
    Self {
      mask: self.mask | other.mask,
      inv,
      truth: f(&self.expand_set(other.mask), &other.expand_set(self.mask)),
    }
  }
}

fn pos_of_set_bits(mut mask: u64) -> SmallVec<[u8; 6]> {
  let mut pos = SmallVec::with_capacity(mask.count_ones().try_into().unwrap());
  while mask.trailing_zeros() < 64 {
    pos.push(mask.trailing_zeros().try_into().unwrap());
    mask ^= 1 << mask.trailing_zeros();
  }
  pos
}

/// Iterator over every possible value under the mask.
fn iter_masked(mask: u64) -> impl Iterator<Item = u64> + Clone + 'static {
  let pos = pos_of_set_bits(mask);
  let empty_zero = pos.is_empty().then_some(0);
  (0u64..1 << mask.count_ones())
    .map(move |x| pos.iter().enumerate().map(|(i, p)| ((x >> i) & 1) << p).fold(0, Add::add))
    .chain(empty_zero)
}

impl Display for TruthTable {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    write!(f, "({}{:b}) {{", if f.alternate() { "0b" } else { "" }, self.mask)?;
    let possible_values = self.possible_values_masked();
    let mut iter = possible_values.iter();
    if let Some(first) = iter.next() {
      if f.alternate() {
        f.write_str("0b")?;
      }
      for _ in 0..first.leading_zeros() - self.mask.leading_zeros() {
        f.write_char('0')?;
      }
      if *first > 0 {
        write!(f, "{:b}", first)?;
      }
      for val in iter {
        f.write_str(", ")?;
        if f.alternate() {
          f.write_str("0b")?;
        }
        for _ in 0..val.leading_zeros() - self.mask.leading_zeros() {
          f.write_char('0')?;
        }
        if *val > 0 {
          write!(f, "{:b}", val)?;
        }
      }
    }
    f.write_char('}')
  }
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

  #[test]
  fn test_truth_table() {
    let op1 = Op::all(0b0100);
    let op2 = Op::not_all(0b1010);
    let tt = op1.to_truth_table().or(&op2.to_truth_table()).into_owned();
    println!("{}", tt);
  }
}
