//! Dice-coefficient similarity scoring over normalized trees, used by
//! near-duplicate grouping.

use std::mem::discriminant;

use crate::calculation;
use crate::calculation::RatioFailure;
use crate::node::NodeKind;
use crate::node::NormalizedNode;
use crate::node::count_nodes;

/// Original tree and matching-node counts used by the Dice calculation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimilarityCounts {
  /// Nodes in the first tree, excluding absent sentinels.
  pub first:    usize,
  /// Nodes in the second tree, excluding absent sentinels.
  pub second:   usize,
  /// Matching nodes in the shared positional traversal.
  pub matching: usize,
}

/// A completed Dice calculation with its original integer evidence.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SimilarityScore {
  /// Original populations and matching-node count.
  pub counts: SimilarityCounts,
  /// Rounded binary64 score used for threshold comparisons.
  pub value:  f64,
}

/// The calculation step that could not produce a Dice score.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SimilarityFailureCause {
  /// Matching nodes exceeded the population of at least one tree.
  #[error("matching nodes exceed a compared tree's node count")]
  InvalidMatchingCount,
  /// The combined tree population exceeded the native counting representation.
  #[error("the combined tree-node count exceeds usize capacity")]
  NodeTotalOverflow,
  /// Twice the matched population exceeded the native counting representation.
  #[error("twice the matching-node count exceeds usize capacity")]
  MatchingTotalOverflow,
  /// Rounded ratio conversion or calculation failed.
  #[error(transparent)]
  Ratio(#[from] Box<RatioFailure>),
}

/// A failed Dice calculation with every original integer count retained.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot calculate similarity from {counts:?}: {source}")]
pub struct SimilarityFailure {
  /// Original counts before accumulation, scaling, or binary64 conversion.
  pub counts: SimilarityCounts,
  /// Exact validation or calculation failure.
  pub source: SimilarityFailureCause,
}

impl SimilarityCounts {
  /// Calculate the Dice coefficient while retaining all input counts on failure.
  fn score(self) -> Result<SimilarityScore, SimilarityFailure> {
    self
      .calculate()
      .map(|score| SimilarityScore {
        counts: self,
        value:  score,
      })
      .map_err(|source| SimilarityFailure {
        counts: self,
        source,
      })
  }

  /// Validate matching populations and preserve the original rounded calculation order.
  fn calculate(&self) -> Result<f64, SimilarityFailureCause> {
    if self.matching > self.first.min(self.second) {
      return Err(SimilarityFailureCause::InvalidMatchingCount);
    }
    if self.first == 0 && self.second == 0 {
      return Ok(1.0);
    }
    let total = self
      .first
      .checked_add(self.second)
      .ok_or(SimilarityFailureCause::NodeTotalOverflow)?;
    let doubled = self
      .matching
      .checked_mul(2)
      .ok_or(SimilarityFailureCause::MatchingTotalOverflow)?;
    // Scaling an integer by two commutes with binary64 count rounding; the
    // numerator therefore matches the original `2.0 * rounded_matching` value.
    calculation::ratio(doubled, total).map_err(|source| SimilarityFailureCause::Ratio(Box::new(source)))
  }
}

/// Compute a similarity score between two normalized trees using the Dice coefficient.
/// Returns a value between 0.0 (completely different) and 1.0 (identical).
///
/// score = (2 * `matching_nodes`) / (`nodes_a` + `nodes_b`)
///
/// Children are compared positionally via `zip`, so when two same-kind nodes have
/// different child counts, only the shared prefix is compared; extra children in the
/// longer list are not matched. This makes the score a conservative underestimate
/// when child counts differ.
///
/// # Errors
///
/// Returns every original integer count with a validation, accumulation, or
/// rounded-ratio failure. The borrowed input trees remain available to the caller.
#[allow(
  clippy::single_call_fn,
  reason = "Tree similarity owns positional matching and the checked Dice calculation shared by language-independent grouping."
)]
pub fn similarity_score(first: &NormalizedNode, second: &NormalizedNode) -> Result<SimilarityScore, SimilarityFailure> {
  SimilarityCounts {
    first:    count_nodes(first),
    second:   count_nodes(second),
    matching: count_matching(first, second),
  }
  .score()
}

/// Count matching nodes between two trees by traversing in parallel.
/// Two nodes "match" if their kind (discriminant + immediate data) are equal.
/// None sentinel nodes contribute 0 to matching.
fn count_matching(first: &NormalizedNode, second: &NormalizedNode) -> usize {
  if first.is_none() || second.is_none() {
    return 0;
  }
  if discriminant(&first.kind) != discriminant(&second.kind) {
    return 0;
  }
  // MacroCall: different names = no match (no recursion into children)
  if let NodeKind::MacroCall {
    name: ref first_name,
  } = first.kind
    && let NodeKind::MacroCall {
      name: ref second_name,
    } = second.kind
    && first_name != second_name
  {
    return 0;
  }
  first
    .children
    .iter()
    .zip(&second.children)
    .map(|(first_child, second_child)| count_matching(first_child, second_child))
    .fold(usize::from(first.kind == second.kind), usize::saturating_add)
}

#[cfg(test)]
mod tests {
  use strict_test_support::ConditionFailure;
  use strict_test_support::ensure;

  use super::SimilarityCounts;
  use super::SimilarityFailure;
  use super::SimilarityFailureCause;
  use super::SimilarityScore;
  use super::similarity_score;
  use crate::node::BinOpKind;
  use crate::node::LiteralKind;
  use crate::node::NodeKind;
  use crate::node::NormalizedNode;
  use crate::node::PlaceholderKind;

  /// Complete calculation outcomes retained when a similarity expectation fails.
  #[derive(Debug, thiserror::Error)]
  enum SimilarityTestFailure {
    /// Original count validation or checked accumulation returned an unexpected failure.
    #[error("count calculation expectation failed: {source}; observed: {observed:?}; expected: {expected:?}")]
    CountFailure {
      /// Complete observed score or calculation failure.
      observed: Box<Result<SimilarityScore, SimilarityFailure>>,
      /// Complete expected failure, including original counts.
      expected: SimilarityFailure,
      /// Failed behavioral expectation.
      source:   ConditionFailure,
    },
    /// A score or its original integer evidence differed from the expected calculation.
    #[error("similarity expectation failed: {source}; observed: {observed:?}; expected: {expected:?}")]
    Score {
      /// Complete score or calculation failure.
      observed: Box<Result<SimilarityScore, SimilarityFailure>>,
      /// Expected original counts and rounded score.
      expected: SimilarityScore,
      /// Failed behavioral expectation.
      source:   ConditionFailure,
    },
    /// Reversing the input trees changed their score or matching population.
    #[error("similarity symmetry failed: {source}; forward: {forward:?}; reverse: {reverse:?}")]
    Symmetry {
      /// Complete forward calculation.
      forward: Box<Result<SimilarityScore, SimilarityFailure>>,
      /// Complete reverse calculation.
      reverse: Box<Result<SimilarityScore, SimilarityFailure>>,
      /// Failed behavioral expectation.
      source:  ConditionFailure,
    },
  }

  /// Describe the complete expected Dice calculation for a normalized-tree fixture.
  const fn expected_score(first: usize, second: usize, matching: usize, value: f64) -> SimilarityScore {
    SimilarityScore {
      counts: SimilarityCounts {
        first,
        second,
        matching,
      },
      value,
    }
  }

  /// Compare original counts and binary64 score together, retaining any native failure.
  fn check_score(
    observed: Result<SimilarityScore, SimilarityFailure>,
    expected: &SimilarityScore,
    contract: &'static str,
  ) -> Result<(), SimilarityTestFailure> {
    ensure(
      observed
        .as_ref()
        .is_ok_and(|score| score.counts == expected.counts && score.value.to_bits() == expected.value.to_bits()),
      contract,
    )
    .map(drop)
    .map_err(|source| SimilarityTestFailure::Score {
      observed: Box::new(observed),
      expected: *expected,
      source,
    })
  }

  /// Construct a normalized variable at the supplied binding index.
  fn var(idx: usize) -> NormalizedNode {
    NormalizedNode::leaf(NodeKind::Placeholder(PlaceholderKind::Variable, idx))
  }

  /// Construct the normalized integer-literal class.
  fn int_lit() -> NormalizedNode {
    NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Int))
  }

  #[test]
  fn invalid_matching_and_overflowing_totals_retain_original_counts() -> Result<(), SimilarityTestFailure> {
    for (counts, failure) in [
      (
        SimilarityCounts {
          first:    1,
          second:   2,
          matching: 2,
        },
        SimilarityFailureCause::InvalidMatchingCount,
      ),
      (
        SimilarityCounts {
          first:    usize::MAX,
          second:   1,
          matching: 1,
        },
        SimilarityFailureCause::NodeTotalOverflow,
      ),
    ] {
      let observed = counts.score();
      let expected = SimilarityFailure {
        counts,
        source: failure,
      };
      ensure(
        observed.as_ref().err() == Some(&expected),
        "failed Dice calculations retain original counts and the exact rejected step",
      )
      .map(drop)
      .map_err(|source| SimilarityTestFailure::CountFailure {
        observed: Box::new(observed),
        expected,
        source,
      })?;
    }
    Ok(())
  }

  /// Equal normalized leaves contribute a complete match.
  #[test]
  fn identical_leaves_score_one() -> Result<(), SimilarityTestFailure> {
    let first = int_lit();
    let second = int_lit();
    check_score(
      similarity_score(&first, &second),
      &expected_score(1, 1, 1, 1.0),
      "identical leaves match completely",
    )
  }

  /// Unrelated node kinds contribute no matching nodes.
  #[test]
  fn completely_different_kinds_score_zero() -> Result<(), SimilarityTestFailure> {
    let first = int_lit();
    let second = NormalizedNode::leaf(NodeKind::PatWild);
    check_score(
      similarity_score(&first, &second),
      &expected_score(1, 1, 0, 0.0),
      "unrelated node kinds do not match",
    )
  }

  /// Two absent trees retain the defined complete-match score.
  #[test]
  fn both_none_sentinels_score_one() -> Result<(), SimilarityTestFailure> {
    let first = NormalizedNode::none();
    let second = NormalizedNode::none();
    check_score(
      similarity_score(&first, &second),
      &expected_score(0, 0, 0, 1.0),
      "two absent nodes represent the same empty tree",
    )
  }

  /// An absent tree cannot match a present node.
  #[test]
  fn none_vs_real_node_score_zero() -> Result<(), SimilarityTestFailure> {
    let absent = NormalizedNode::none();
    let present = int_lit();
    check_score(
      similarity_score(&absent, &present),
      &expected_score(0, 1, 0, 0.0),
      "an absent node does not match a real node",
    )
  }

  /// Unpaired children contribute to tree size without contributing a match.
  #[test]
  fn different_child_counts_uses_shared_prefix() -> Result<(), SimilarityTestFailure> {
    // Block with 3 children vs Block with 5 children
    // zip compares only first 3 pairs; extra 2 are unmatched
    let shorter = NormalizedNode::with_children(NodeKind::Block, vec![int_lit(), int_lit(), int_lit()]);
    let longer = NormalizedNode::with_children(NodeKind::Block, vec![int_lit(), int_lit(), int_lit(), var(0), var(1)]);
    let score = similarity_score(&shorter, &longer);
    // matching = Block(1) + 3 Int(1) = 4
    // nodes_a = 4, nodes_b = 6 => score = 8/10 = 0.8
    check_score(
      score,
      &expected_score(4, 6, 4, 0.8),
      "only the shared child prefix contributes matching nodes",
    )
  }

  /// An absent else sentinel preserves the positions and matches of preceding children.
  #[test]
  fn if_with_else_vs_if_without_else() -> Result<(), SimilarityTestFailure> {
    // If -> [condition, then, else_or_None]
    let with_else = NormalizedNode::with_children(NodeKind::If, vec![
      var(0),
      NormalizedNode::with_children(NodeKind::Block, vec![int_lit()]),
      NormalizedNode::with_children(NodeKind::Block, vec![int_lit()]),
    ]);
    let without_else = NormalizedNode::with_children(NodeKind::If, vec![
      var(0),
      NormalizedNode::with_children(NodeKind::Block, vec![int_lit()]),
      NormalizedNode::none(),
    ]);
    let score = similarity_score(&with_else, &without_else);
    // with_else: If + var + Block + Int + Block + Int = 6 nodes
    // without_else: If + var + Block + Int + None(0) = 4 nodes
    // matching: If(1) + var(1) + Block(1) + Int(1) + (Block vs None = 0) = 4
    // score = 2*4 / (6+4) = 0.8
    check_score(
      score,
      &expected_score(6, 4, 4, 0.8),
      "an absent else branch contributes neither a node nor a match",
    )
  }

  /// A missing return value leaves only the return nodes matched.
  #[test]
  fn return_with_vs_without_value() -> Result<(), SimilarityTestFailure> {
    // Return -> [value] vs Return -> []
    let with_val = NormalizedNode::with_children(NodeKind::Return, vec![int_lit()]);
    let without_val = NormalizedNode::with_children(NodeKind::Return, vec![]);
    let score = similarity_score(&with_val, &without_val);
    // with_val: Return + Int = 2 nodes; without_val: Return = 1 node
    // matching: Return(1) + zip(empty) = 1
    // score = 2*1 / (2+1) = 2/3
    check_score(
      score,
      &expected_score(2, 1, 1, 0.666_666_666_666_666_6),
      "only the return node matches when one return value is absent",
    )
  }

  /// Different operators can preserve child matches without matching themselves.
  #[test]
  fn same_discriminant_different_data_no_self_match() -> Result<(), SimilarityTestFailure> {
    // BinaryOp(Add) vs BinaryOp(Sub) — same discriminant, different data
    let addition = NormalizedNode::with_children(NodeKind::BinaryOp(BinOpKind::Add), vec![var(0), int_lit()]);
    let subtraction = NormalizedNode::with_children(NodeKind::BinaryOp(BinOpKind::Sub), vec![var(0), int_lit()]);
    let score = similarity_score(&addition, &subtraction);
    // matching: BinOp self_match=0 (Add!=Sub) + var(1) + int(1) = 2
    // nodes_a = 3, nodes_b = 3 => score = 4/6 = 0.667
    check_score(
      score,
      &expected_score(3, 3, 2, 0.666_666_666_666_666_6),
      "different operators preserve child matches without matching the operator itself",
    )
  }

  /// A changed macro name rejects the whole call subtree.
  #[test]
  fn macro_call_different_names_score_zero() -> Result<(), SimilarityTestFailure> {
    let first = NormalizedNode::with_children(
      NodeKind::MacroCall {
        name: "println".to_owned(),
      },
      vec![int_lit()],
    );
    let second = NormalizedNode::with_children(
      NodeKind::MacroCall {
        name: "eprintln".to_owned(),
      },
      vec![int_lit()],
    );
    check_score(
      similarity_score(&first, &second),
      &expected_score(2, 2, 0, 0.0),
      "different macro names reject their entire call subtrees",
    )
  }

  /// Matching macro names allow shared arguments to contribute a partial match.
  #[test]
  fn macro_call_same_name_different_args_partial() -> Result<(), SimilarityTestFailure> {
    let first = NormalizedNode::with_children(
      NodeKind::MacroCall {
        name: "println".to_owned(),
      },
      vec![int_lit()],
    );
    let second = NormalizedNode::with_children(
      NodeKind::MacroCall {
        name: "println".to_owned(),
      },
      vec![int_lit(), var(0)],
    );
    let score = similarity_score(&first, &second);
    // a: MacroCall + Int = 2; b: MacroCall + Int + var = 3
    // matching: MacroCall(1) + Int(1) = 2; score = 4/5 = 0.8
    check_score(
      score,
      &expected_score(2, 3, 2, 0.8),
      "same-name macro calls compare their shared arguments",
    )
  }

  /// Swapping the compared trees preserves the similarity score.
  #[test]
  fn similarity_is_symmetric() -> Result<(), SimilarityTestFailure> {
    let first = NormalizedNode::with_children(NodeKind::Block, vec![int_lit(), var(0)]);
    let second = NormalizedNode::with_children(NodeKind::Block, vec![int_lit(), var(0), var(1)]);
    let forward = similarity_score(&first, &second);
    let reverse = similarity_score(&second, &first);
    ensure(
      matches!((forward.as_ref(), reverse.as_ref()), (Ok(original), Ok(reversed))
        if (original.value.to_bits(), original.counts.first, original.counts.second, original.counts.matching)
          == (reversed.value.to_bits(), reversed.counts.second, reversed.counts.first, reversed.counts.matching)),
      "swapping the compared trees preserves the similarity score",
    )
    .map(drop)
    .map_err(|source| SimilarityTestFailure::Symmetry {
      forward: Box::new(forward),
      reverse: Box::new(reverse),
      source,
    })
  }
}
