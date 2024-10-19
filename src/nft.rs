use crate::bgp::flow::{Bitmask, BitmaskFlags, Component, Numeric, NumericFlags, Op, Ops};
use crate::net::{Afi, IpPrefix};
use crate::util::Intersect;
use nftables::{expr, stmt};
use num::Integer;
use smallvec::SmallVec;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::ops::{Add, RangeInclusive};

impl Component {
  // TODO: edge cases (e.g. always true/false); simple case optimization
  pub fn write_nft_stmt(&self, afi: Afi, buf: &mut Vec<stmt::Statement>) -> Option<Vec<Vec<stmt::Statement>>> {
    use Component::*;

    let ip_ver = if afi == Afi::Ipv4 { "ip" } else { "ip6" };
    let icmp_ver = if afi == Afi::Ipv4 { "icmp" } else { "icmpv6" };

    match self {
      DstPrefix(prefix, 0) => buf.push(prefix_stmt("daddr", *prefix)),
      SrcPrefix(prefix, 0) => buf.push(prefix_stmt("saddr", *prefix)),
      DstPrefix(pattern, offset) => pattern_stmt(false, *pattern, *offset, buf),
      SrcPrefix(pattern, offset) => pattern_stmt(true, *pattern, *offset, buf),
      Protocol(ops) => buf.push(range_stmt(
        expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta { key: expr::MetaKey::L4proto })),
        ops,
      )),
      Port(ops) => {
        let mut dup = buf.clone();
        buf.push(range_stmt(make_payload_field("th", "dport"), ops));
        dup.push(range_stmt(make_payload_field("th", "sport"), ops));
        return Some(vec![dup]);
      }
      DstPort(ops) => buf.push(range_stmt(make_payload_field("th", "dport"), ops)),
      SrcPort(ops) => buf.push(range_stmt(make_payload_field("th", "sport"), ops)),
      IcmpType(ops) => buf.push(range_stmt(make_payload_field(icmp_ver, "type"), ops)),
      IcmpCode(ops) => buf.push(range_stmt(make_payload_field(icmp_ver, "code"), ops)),
      TcpFlags(ops) => {
        let truth_table = ops.to_truth_table();
        // HACK: does nftables itself support 64-bit integers? We shrink it for now.
        buf.push(make_match(
          if truth_table.inv {
            stmt::Operator::NEQ
          } else {
            stmt::Operator::EQ
          },
          expr::Expression::BinaryOperation(expr::BinaryOperation::AND(
            Box::new(make_payload_field("tcp", "flags")),
            Box::new(expr::Expression::Number(truth_table.mask as u32)),
          )),
          expr::Expression::Named(expr::NamedExpression::Set(
            (truth_table.truth.iter().copied())
              .map(|x| expr::SetItem::Element(expr::Expression::Number(x as u32)))
              .collect(),
          )),
        ))
      }
      PacketLen(ops) => {
        let ops = if afi == Afi::Ipv4 {
          Cow::Borrowed(ops)
        } else {
          let mut ops = ops.clone();
          ops.offset(-40);
          Cow::Owned(ops)
        };
        buf.push(range_stmt(make_payload_field(ip_ver, "length"), &ops))
      }
      Dscp(ops) => buf.push(range_stmt(make_payload_field(ip_ver, "dscp"), ops)),
      Fragment(ops) => {
        // TODO: reduce clone
        // int frag_op_value = [LF,FF,IsF,DF]
        // possible: [DF], [IsF], [FF], [LF], [LF,IsF](=[LF])
        let mask = if afi == Afi::Ipv4 { 0b1111 } else { 0b1110 };
        let tt = ops.to_truth_table();
        let tt = tt.shrink_set(mask);
        let valid_set = [0b0001, 0b0010, 0b1010, 0b0100, 0b1000].into_iter().collect();
        let mut new_set: BTreeSet<_> = tt.possible_values_masked().intersection(&valid_set).copied().collect();
        if new_set.remove(&0b1010) {
          new_set.insert(0b1000);
        }
        let mut iter = new_set.into_iter().peekable();
        let mut stmts = SmallVec::<[_; 4]>::new();

        let frag_off = make_payload_field(if afi == Afi::Ipv4 { "ip" } else { "frag" }, "frag-off");
        let mf = if afi == Afi::Ipv4 {
          make_payload_raw(expr::PayloadBase::NH, 18, 1)
        } else {
          make_payload_field("frag", "more-fragments")
        };

        // DF (IPv4)
        if let Some(0b0001) = iter.peek() {
          iter.next();
          stmts.push((
            make_match(
              stmt::Operator::EQ,
              make_payload_raw(expr::PayloadBase::NH, 17, 1),
              expr::Expression::Number(1),
            ),
            None,
          ));
        }
        // IsF: {ip,frag} frag-off != 0
        if let Some(0b0010) = iter.peek() {
          iter.next();
          stmts.push((
            make_match(stmt::Operator::NEQ, frag_off.clone(), expr::Expression::Number(0)),
            None,
          ));
        }
        // FF: {ip,frag} frag-off == 0 && MF == 1
        if let Some(0b0100) = iter.peek() {
          iter.next();
          stmts.push((
            make_match(stmt::Operator::EQ, frag_off.clone(), expr::Expression::Number(0)),
            Some(make_match(stmt::Operator::EQ, mf.clone(), expr::Expression::Number(1))),
          ));
        }
        // LF: {ip,frag} frag-off != 0 && MF == 0
        if let Some(0b1000) = iter.peek() {
          iter.next();
          stmts.push((
            make_match(stmt::Operator::NEQ, frag_off, expr::Expression::Number(0)),
            Some(make_match(stmt::Operator::EQ, mf, expr::Expression::Number(0))),
          ));
        }

        if !stmts.is_empty() {
          let len_gt_1 = stmts.len() > 1;
          let mut iter = stmts.into_iter();
          let (first1, first2) = iter.next().unwrap();
          buf.extend([Some(first1), first2].into_iter().flatten());
          if len_gt_1 {
            let split = iter
              .map(|(s1, s2)| buf.iter().cloned().chain([Some(s1), s2].into_iter().flatten()).collect())
              .collect();
            return Some(split);
          }
        }
      }
      FlowLabel(ops) => buf.push(range_stmt(make_payload_field("ip6", "flowlabel"), ops)),
    }
    None
  }
}

fn make_match(op: stmt::Operator, left: expr::Expression, right: expr::Expression) -> stmt::Statement {
  stmt::Statement::Match(stmt::Match { left, right, op })
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

fn prefix_stmt(field: impl ToString, prefix: IpPrefix) -> stmt::Statement {
  make_match(
    stmt::Operator::EQ,
    make_payload_field(if prefix.afi() == Afi::Ipv4 { "ip" } else { "ip6" }, field),
    expr::Expression::Named(expr::NamedExpression::Prefix(expr::Prefix {
      addr: Box::new(expr::Expression::String(format!("{}", prefix.prefix()))),
      len: prefix.len().into(),
    })),
  )
}

fn pattern_stmt(src: bool, pattern: IpPrefix, offset: u8, buf: &mut Vec<stmt::Statement>) {
  let addr_offset = if src { 192 } else { 64 };

  buf.push(make_match(
    stmt::Operator::EQ,
    expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta { key: expr::MetaKey::Nfproto })),
    expr::Expression::String("ipv6".into()),
  ));

  let start_32bit = offset.next_multiple_of(32);
  let pre_rem = start_32bit - offset;
  let end_32bit = pattern.len().prev_multiple_of(&32); // this uses num::Integer, not std
  let post_rem = pattern.len() - end_32bit;

  let IpAddr::V6(ip) = pattern.prefix() else {
    unreachable!();
  };
  if pre_rem > 0 {
    let num = ip.to_bits() >> (128 - start_32bit);
    buf.push(make_match(
      stmt::Operator::EQ,
      make_payload_raw(expr::PayloadBase::NH, addr_offset + offset as u32, pre_rem.into()),
      expr::Expression::Number(num.try_into().unwrap()),
    ));
  }
  debug_assert!(start_32bit <= end_32bit);
  for i in (start_32bit..end_32bit).step_by(32) {
    let num = (ip.to_bits() >> (pattern.len() - 32 - i)) as u32;
    buf.push(make_match(
      stmt::Operator::EQ,
      make_payload_raw(expr::PayloadBase::NH, addr_offset + i as u32, 32),
      expr::Expression::Number(num),
    ));
  }
  if post_rem > 0 {
    let num = ((ip.to_bits() >> (128 - pattern.len())) as u32) & (u32::MAX >> (32 - post_rem));
    buf.push(make_match(
      stmt::Operator::EQ,
      make_payload_raw(expr::PayloadBase::NH, addr_offset + end_32bit as u32, post_rem.into()),
      expr::Expression::Number(num),
    ));
  }
}

fn range_stmt(left: expr::Expression, ops: &Ops<Numeric>) -> stmt::Statement {
  let allowed = ops
    .to_ranges()
    .into_iter()
    .map(|x| {
      let (start, end) = x.into_inner();
      // HACK: does nftables itself support 64-bit integers? We shrink it for now.
      let expr = if start == end {
        expr::Expression::Number(start as u32)
      } else {
        expr::Expression::Range(expr::Range {
          range: vec![
            expr::Expression::Number(start as u32),
            expr::Expression::Number(end as u32),
          ],
        })
      };
      expr::SetItem::Element(expr)
    })
    .collect();
  make_match(
    stmt::Operator::EQ,
    left,
    expr::Expression::Named(expr::NamedExpression::Set(allowed)),
  )
}

impl Ops<Numeric> {
  pub fn to_ranges(&self) -> Vec<RangeInclusive<u64>> {
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
}

impl Ops<Bitmask> {
  pub fn to_truth_table(&self) -> TruthTable {
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
  pub fn to_ranges(self) -> Option<(RangeInclusive<u64>, Option<RangeInclusive<u64>>)> {
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

  pub fn to_range_iter(self) -> impl Iterator<Item = RangeInclusive<u64>> + Clone {
    self
      .to_ranges()
      .map(|(a, b)| [Some(a), b].into_iter().flatten())
      .into_iter()
      .flatten()
  }

  /// Offset the operator by adding n (no overflow) to every value compared.
  pub fn offset(self, n: i64) -> Self {
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
  true
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruthTable {
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

  pub fn shrink_set(&self, other_mask: u64) -> Cow<Self> {
    let new_mask = self.mask & other_mask;
    if new_mask == self.mask {
      Cow::Borrowed(self)
    } else {
      Cow::Owned(Self {
        mask: new_mask,
        inv: self.inv,
        truth: self.truth.iter().map(|v| v & new_mask).collect(),
      })
    }
  }

  fn expand_set(&self, other_mask: u64) -> Cow<BTreeSet<u64>> {
    if self.mask | other_mask == self.mask {
      Cow::Borrowed(&self.truth)
    } else {
      let rem = other_mask & !self.mask;
      let set = iter_masked(rem)
        .map(|a| self.truth.iter().map(move |b| a | b))
        .flatten()
        .collect();
      Cow::Owned(set)
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
    pos.push(dbg!(mask.trailing_zeros()).try_into().unwrap());
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
