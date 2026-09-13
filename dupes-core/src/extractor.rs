//! Sub-function extraction and trivial-shape classification.
//!
//! Walks normalized bodies for branch/arm/loop/closure sub-units (if-chains
//! grouped as wholes) and tags low-signal shapes against the suppression
//! rules.

use std::collections::HashMap;

use crate::code_unit::CodeUnitKind;
use crate::fingerprint::Fingerprint;
use crate::node;
use crate::node::BinOpKind;
use crate::node::NodeKind;
use crate::node::NormalizedNode;
use crate::split_runs_by;
use crate::suppression::RuleId;
use crate::suppression::SuppressionPolicy;

/// A sub-unit extracted from a normalized function body.
#[derive(Debug, PartialEq, Eq)]
pub struct SubUnit {
  /// Structural kind of the sub-unit (branch, arm, loop body, ...).
  pub kind:         CodeUnitKind,
  /// The reindexed normalized subtree.
  pub node:         NormalizedNode,
  /// Number of nodes in the reindexed subtree.
  pub node_count:   usize,
  /// Human-readable description rendered as the unit name.
  pub description:  String,
  /// Suppression rule that tagged this sub-unit as a low-signal candidate.
  pub suppressed:   Option<RuleId>,
  /// For if-branch sub-units, the fingerprint of the owning if-chain unit.
  pub parent_chain: Option<Fingerprint>,
}

/// Bodies at or above this node count are never tagged as trivial shapes.
///
/// A large boolean projection or plumbing chain is worth seeing even when its
/// shape matches a trivial rule, while real setters and accessors sit well
/// under the cap.
pub const TRIVIAL_BODY_MAX_NODES: usize = 24;

/// Extract candidate sub-units from a normalized AST node.
///
/// Walks the tree recursively and extracts natural compound structures
/// (if branches, match arm bodies, loop bodies, closure bodies).
/// Each sub-tree is re-indexed to canonical placeholder form.
/// Only sub-trees meeting `min_node_count` are returned.
#[must_use]
#[allow(
  clippy::single_call_fn,
  reason = "This public extraction boundary is shared by language analyzers."
)]
pub fn extract_sub_units(node: &NormalizedNode, min_node_count: usize) -> Vec<SubUnit> {
  let mut results = Vec::new();
  extract_recursive(node, min_node_count, &mut results);
  results
}

/// Classify an extracted sub-unit against the suppression rules.
///
/// Direct extraction still returns every natural sub-tree that meets the node
/// threshold. The analysis pipeline tags each sub-unit with the first
/// matching enabled rule so tiny placeholders, projections, and simple
/// predicates do not become standalone visible findings; `None` means the
/// sub-unit is a fully visible candidate.
#[must_use]
#[allow(
  clippy::single_call_fn,
  reason = "This public classifier owns sub-unit rule precedence for the analysis pipeline."
)]
pub fn classify_sub_unit(node: &NormalizedNode, policy: &SuppressionPolicy) -> Option<RuleId> {
  let expression = peel_transparent_single_child(node);
  if !has_reportable_structure(expression) {
    return policy.allow(RuleId::SubNoStructure);
  }
  low_information_rule(expression).and_then(|rule| policy.allow(rule))
}

/// Extract natural compound bodies and recurse through their descendants.
fn extract_recursive(node: &NormalizedNode, min_node_count: usize, results: &mut Vec<SubUnit>) {
  // Block -> statement sequence: runs of consecutive `if` statements form
  // one coherent chain unit (for example option-to-field setter clusters),
  // while retaining branch units linked to their owning chain.
  if matches!(node.kind, NodeKind::Block) && extract_if_chains(node, min_node_count, results) {
    return;
  }

  // If -> [condition, then_branch, else_or_None]
  if matches!(node.kind, NodeKind::If) {
    add_if_branches(node, min_node_count, results, None);
  }
  if matches!(node.kind, NodeKind::Match) {
    // Match -> [expr, arm0, arm1, ...]
    // Each arm is MatchArm -> [pattern, guard_or_None, body]
    for (index, arm) in node.children.iter().skip(1).enumerate() {
      if let Some(body) = arm.children.get(2) {
        let description = format!("match arm {}", index.saturating_add(1));
        results.extend(extract_sub_unit(body, CodeUnitKind::MatchArm, &description, min_node_count));
      }
    }
  }
  // Loop -> [body]
  if matches!(node.kind, NodeKind::Loop) {
    try_add_child(node, 0, CodeUnitKind::LoopBody, "loop body", min_node_count, results);
  }
  // While -> [condition, body]
  if matches!(node.kind, NodeKind::While) {
    try_add_child(node, 1, CodeUnitKind::LoopBody, "while body", min_node_count, results);
  }
  // ForLoop -> [pat, iter, body]
  if matches!(node.kind, NodeKind::ForLoop) {
    try_add_child(node, 2, CodeUnitKind::LoopBody, "for body", min_node_count, results);
  }
  // Closure -> [body, param0, ...]
  if matches!(node.kind, NodeKind::Closure) {
    try_add_child(node, 0, CodeUnitKind::Block, "closure body", min_node_count, results);
  }

  // Always recurse into all children
  for child in &node.children {
    extract_recursive(child, min_node_count, results);
  }
}

/// Emit the then/else branch units of an `if` node, linked to the owning
/// chain when the `if` belongs to one.
fn add_if_branches(node: &NormalizedNode, min_node_count: usize, results: &mut Vec<SubUnit>, parent_chain: Option<Fingerprint>) {
  let mut add = |branch: &NormalizedNode, label: &str| {
    if let Some(mut unit) = extract_sub_unit(branch, CodeUnitKind::IfBranch, label, min_node_count) {
      unit.parent_chain = parent_chain;
      results.push(unit);
    }
  };
  if let Some(then_branch) = node.children.get(1) {
    add(then_branch, "if-then branch");
  }
  if let Some(else_branch) = node.children.get(2)
    && !else_branch.is_none()
  {
    add(else_branch, "if-else branch");
  }
}

/// Extract if-chain units from a block's statement children.
///
/// Returns false when the block has no chains, in which case the caller
/// falls through to ordinary extraction. When chains exist, the chain units
/// are added, per-branch units of chained statements are emitted linked to
/// their owning chain via `parent_chain`, and the children are recursed here
/// instead.
#[allow(
  clippy::single_call_fn,
  reason = "This operation emits chain ownership before recursively extracting branch bodies."
)]
fn extract_if_chains(node: &NormalizedNode, min_node_count: usize, results: &mut Vec<SubUnit>) -> bool {
  let statements: Vec<_> = node.children.iter().enumerate().collect();
  let chain_members: Vec<_> = statements
    .chunk_by(|&(_, previous), &(_, current)| {
      matches!(statement_if(previous).kind, NodeKind::If) && matches!(statement_if(current).kind, NodeKind::If)
    })
    .filter(|run| run.len() >= 2)
    .flatten()
    .copied()
    .collect();
  if chain_members.is_empty() {
    return false;
  }
  let mut owning_chain: HashMap<usize, Fingerprint> = HashMap::new();
  for run in split_runs_by(&chain_members, |previous, current| previous.0.checked_add(1) == Some(current.0)) {
    let chain = NormalizedNode::with_children(
      NodeKind::Block,
      run.iter().map(|&(_, statement)| statement_if(statement).clone()).collect(),
    );
    let description = format!("if chain ({} branches)", run.len());
    if let Some(unit) = extract_sub_unit(&chain, CodeUnitKind::IfChain, &description, min_node_count) {
      let chain_fingerprint = Fingerprint::from_node(&unit.node);
      owning_chain.extend(run.iter().map(|&(index, _)| (index, chain_fingerprint)));
      results.push(unit);
    }
  }
  for (index, child) in node.children.iter().enumerate() {
    if chain_members.iter().any(|&(position, _)| position == index) {
      let chained_if = statement_if(child);
      if let Some(&chain_fingerprint) = owning_chain.get(&index) {
        // Branch units stay extracted but carry their owning chain so
        // the pipeline can treat them as covered while the chain
        // groups as a whole.
        add_if_branches(chained_if, min_node_count, results, Some(chain_fingerprint));
      }
      for nested in &chained_if.children {
        extract_recursive(nested, min_node_count, results);
      }
    } else {
      extract_recursive(child, min_node_count, results);
    }
  }
  true
}

/// Borrow a child only when the sequence contains exactly one node.
const fn single_child(children: &[NormalizedNode]) -> Option<&NormalizedNode> {
  if children.len() == 1 { children.first() } else { None }
}

/// Return the `if` expression of a statement child, peeling a `Semi` wrapper.
const fn statement_if(node: &NormalizedNode) -> &NormalizedNode {
  if matches!(node.kind, NodeKind::Semi)
    && let Some(expression) = single_child(node.children.as_slice())
    && matches!(expression.kind, NodeKind::If)
  {
    return expression;
  }
  node
}

/// Extract the child at `child_index` as a sub-unit, if present.
fn try_add_child(
  node: &NormalizedNode,
  child_index: usize,
  kind: CodeUnitKind,
  description: &str,
  min_node_count: usize,
  results: &mut Vec<SubUnit>,
) {
  if let Some(child) = node.children.get(child_index) {
    results.extend(extract_sub_unit(child, kind, description, min_node_count));
  }
}

/// Construct a canonically indexed sub-unit when it meets the extraction threshold.
fn extract_sub_unit(node: &NormalizedNode, kind: CodeUnitKind, description: &str, min_node_count: usize) -> Option<SubUnit> {
  let reindexed = node::reindex_placeholders(node);
  let node_count = node::count_nodes(&reindexed);
  if node_count < min_node_count {
    return None;
  }
  Some(SubUnit {
    suppressed: None,
    parent_chain: None,
    kind,
    node: reindexed,
    node_count,
    description: description.to_owned(),
  })
}

/// Detect bindings, effects, control flow, or computations within a subtree.
fn has_reportable_structure(node: &NormalizedNode) -> bool {
  if matches!(
    node.kind,
    NodeKind::LetBinding
      | NodeKind::Assign
      | NodeKind::Return
      | NodeKind::Break
      | NodeKind::Continue
      | NodeKind::Call
      | NodeKind::MethodCall
      | NodeKind::MacroCall { .. }
      | NodeKind::If
      | NodeKind::Match
      | NodeKind::Loop
      | NodeKind::While
      | NodeKind::ForLoop
      | NodeKind::Yield
      | NodeKind::Await
      | NodeKind::Try
      | NodeKind::StructInit
  ) {
    return true;
  }
  if let NodeKind::BinaryOp(operator) = node.kind {
    return is_reportable_binary_op(operator) || node.children.iter().any(has_reportable_structure);
  }
  matches!(
    node.kind,
    NodeKind::UnaryOp(_)
      | NodeKind::Block
      | NodeKind::Paren
      | NodeKind::Semi
      | NodeKind::Tuple
      | NodeKind::Array
      | NodeKind::Set
      | NodeKind::Repeat
      | NodeKind::Range
      | NodeKind::Reference { .. }
      | NodeKind::Cast
      | NodeKind::FieldAccess
      | NodeKind::Index
      | NodeKind::Path
      | NodeKind::Closure
  ) && node.children.iter().any(has_reportable_structure)
}

/// Distinguish computation operators from comparisons and boolean projections.
const fn is_reportable_binary_op(operator: BinOpKind) -> bool {
  !matches!(
    operator,
    BinOpKind::Eq
      | BinOpKind::Lt
      | BinOpKind::Le
      | BinOpKind::Ne
      | BinOpKind::Ge
      | BinOpKind::Gt
      | BinOpKind::And
      | BinOpKind::Or
      | BinOpKind::In
      | BinOpKind::NotIn
      | BinOpKind::Is
      | BinOpKind::IsNot
  )
}

/// The low-information shape of a node, attributed to its suppression rule.
fn low_information_rule(node: &NormalizedNode) -> Option<RuleId> {
  if let NodeKind::BinaryOp(operator) = node.kind {
    return (!is_reportable_binary_op(operator) && children_are_simple_values_or_projections(node)).then_some(RuleId::SubTrivialPredicate);
  }
  // A guard that bails out with an empty or default construction
  // (`return Vec::new()`, `return Config::default()`) carries no
  // structure of its own, and a dispatch return that only forwards
  // plumbing arguments through one call (`return normalize_x(a, b, c)`)
  // repeats wherever a dispatch table repeats; returns that wrap or
  // compute a value (`return Some(x)`, `return f(a + b, c)`) stay
  // reportable.
  if matches!(node.kind, NodeKind::Return) {
    if returns_empty_default(node) {
      return Some(RuleId::SubEmptyDefaultReturn);
    }
    return returns_plumbing_dispatch(node).then_some(RuleId::SubValuePlumbing);
  }
  // A branch that only emits a message (`writeln!(writer, "...")?`)
  // repeats wherever something is printed, not where logic repeats.
  if let NodeKind::MacroCall {
    ref name,
  } = node.kind
  {
    return (MESSAGE_ONLY_MACROS.contains(&name.as_str()) && children_are_simple_values_or_projections(node))
      .then_some(RuleId::SubMessageOnlyMacro);
  }
  // Bare constructor dispatch and value plumbing: calls whose
  // arguments only shuttle simple values through other plain calls
  // (`Box::new(RustAnalyzer::new())`, delegating match arms, visitor
  // forwarding bodies) only matter as part of a larger unit. Closures
  // keep a chain reportable: a pipeline with callback logic is a real
  // refactorable shape.
  if matches!(node.kind, NodeKind::Call | NodeKind::MethodCall) {
    return node
      .children
      .iter()
      .all(is_value_plumbing_expr)
      .then_some(RuleId::SubValuePlumbing);
  }
  if matches!(node.kind, NodeKind::Block | NodeKind::Paren | NodeKind::Semi | NodeKind::Try)
    && let Some(child) = single_child(node.children.as_slice())
  {
    return low_information_rule(child);
  }
  None
}

/// Check that every child is a value or a projection without computation.
fn children_are_simple_values_or_projections(node: &NormalizedNode) -> bool {
  node.children.iter().all(is_simple_value_or_projection)
}

/// Return true when a `Return` node only produces an empty/default value.
#[allow(
  clippy::single_call_fn,
  reason = "The empty-return boundary distinguishes default construction from payload-carrying returns."
)]
fn returns_empty_default(node: &NormalizedNode) -> bool {
  node.children.iter().all(|child| {
    if matches!(child.kind, NodeKind::Literal(_)) {
      return true;
    }
    // `Vec::new()` / `MatchedGroups::default()`: a path called with no
    // arguments. `Some(value)` keeps its argument and stays reportable.
    if matches!(child.kind, NodeKind::Call) {
      return single_child(child.children.as_slice()).is_some_and(is_simple_value_or_projection);
    }
    // `return rel.to_string_lossy()`: forwarding a projection.
    matches!(child.kind, NodeKind::MethodCall) && children_are_simple_values_or_projections(child)
  })
}

/// Return true for a dispatch-style return: exactly one child of kind
/// `Call` with a callee and at least two arguments, all value plumbing
/// (`return normalize_if(node, source, mapping, ctx)`). Two-child calls
/// (`return Some(x)`, `return NormalizedNode::leaf(kind)`) stay reportable.
#[allow(
  clippy::single_call_fn,
  reason = "The dispatch arity boundary must remain distinct from wrapped-value return handling."
)]
fn returns_plumbing_dispatch(node: &NormalizedNode) -> bool {
  let Some(child) = single_child(node.children.as_slice()) else {
    return false;
  };
  matches!(child.kind, NodeKind::Call) && child.children.len() >= 3 && child.children.iter().all(is_value_plumbing_expr)
}

/// Macros whose only effect is writing a message to an output stream.
const MESSAGE_ONLY_MACROS: &[&str] = &["print", "println", "eprint", "eprintln", "write", "writeln"];

/// Return true for expressions that only shuttle values around: simple
/// values/projections, and calls or value macros built from them. Closures
/// are not plumbing; callback logic makes a chain reportable.
fn is_value_plumbing_expr(node: &NormalizedNode) -> bool {
  if is_simple_value_or_projection(node) {
    return true;
  }
  matches!(
    node.kind,
    NodeKind::Call | NodeKind::MethodCall | NodeKind::MacroCall { .. } | NodeKind::Reference { .. } | NodeKind::Paren
  ) && node.children.iter().all(is_value_plumbing_expr)
}

/// Recognize literal values, placeholders, and recursively simple projections.
fn is_simple_value_or_projection(node: &NormalizedNode) -> bool {
  if matches!(
    node.kind,
    NodeKind::Literal(_)
      | NodeKind::Placeholder(..)
      | NodeKind::PatPlaceholder(..)
      | NodeKind::TypePlaceholder(..)
      | NodeKind::PatWild
      | NodeKind::PatLiteral
      | NodeKind::TypeInfer
      | NodeKind::TypeUnit
      | NodeKind::None
      | NodeKind::Opaque
      | NodeKind::Token(_)
  ) {
    return true;
  }
  if matches!(node.kind, NodeKind::Block | NodeKind::Semi)
    && let Some(child) = single_child(node.children.as_slice())
  {
    return is_simple_value_or_projection(child);
  }
  matches!(
    node.kind,
    NodeKind::Path
      | NodeKind::FieldAccess
      | NodeKind::Index
      | NodeKind::Reference { .. }
      | NodeKind::Cast
      | NodeKind::UnaryOp(_)
      | NodeKind::Paren
      | NodeKind::Tuple
      | NodeKind::Array
      | NodeKind::Set
      | NodeKind::Range
      | NodeKind::TypeReference { .. }
      | NodeKind::TypeTuple
      | NodeKind::TypeSlice
      | NodeKind::TypeArray
      | NodeKind::TypePath
      | NodeKind::TypeImplTrait
      | NodeKind::PatTuple
      | NodeKind::PatStruct
      | NodeKind::PatOr
      | NodeKind::PatReference { .. }
      | NodeKind::PatSlice
      | NodeKind::PatRest
      | NodeKind::PatRange
  ) && node.children.iter().all(is_simple_value_or_projection)
}

/// Borrow the expression beneath transparent wrappers containing exactly one child.
const fn peel_transparent_single_child(mut node: &NormalizedNode) -> &NormalizedNode {
  while matches!(node.kind, NodeKind::Block | NodeKind::Paren | NodeKind::Semi)
    && let Some(child) = single_child(node.children.as_slice())
  {
    node = child;
  }
  node
}

/// Classify a top-level function or method body against the suppression rules.
///
/// Whole-body trivial shapes — builder setters, accessor forwarding, and
/// bare boolean projection predicates — repeat wherever the language forces
/// the pattern, so they are tagged rather than reported by default. Bodies
/// with bindings, control flow, arithmetic, closures, or multi-statement
/// behavior stay visible (`None`), as do constructor wrappers that bind
/// constants.
#[must_use]
pub fn classify_top_level_body(body: &NormalizedNode, policy: &SuppressionPolicy) -> Option<RuleId> {
  let expression = peel_transparent_single_child(body);
  if node::count_nodes(expression) >= TRIVIAL_BODY_MAX_NODES {
    return None;
  }
  if is_setter_returning_self(expression) {
    return policy.allow(RuleId::AstSetterReturningSelf);
  }
  if is_forwarding_accessor_body(expression) {
    return policy.allow(RuleId::AstForwardingAccessor);
  }
  if is_trivial_boolean_projection(expression) {
    return policy.allow(RuleId::AstBooleanProjection);
  }
  None
}

/// Classify a standalone closure body against the suppression rules.
///
/// Applies the top-level rules plus the comparator-adapter shape
/// (`key(a).cmp(&key(b))`), which closures repeat at every sort site.
#[must_use]
#[allow(
  clippy::single_call_fn,
  reason = "The public closure classifier adds comparator adaptation to top-level shape classification."
)]
pub fn classify_closure_body(body: &NormalizedNode, policy: &SuppressionPolicy) -> Option<RuleId> {
  classify_top_level_body(body, policy).or_else(|| {
    let expression = peel_transparent_single_child(body);
    if matches!(expression.kind, NodeKind::MethodCall) && expression.children.iter().all(is_value_plumbing_expr) {
      policy.allow(RuleId::AstComparatorAdapter)
    } else {
      None
    }
  })
}

/// `self.field = value; self` builder-setter bodies.
#[allow(
  clippy::single_call_fn,
  reason = "Builder mutation followed by a simple return is a named suppression boundary."
)]
fn is_setter_returning_self(node: &NormalizedNode) -> bool {
  if !matches!(node.kind, NodeKind::Block) {
    return false;
  }
  let Some((returned, operations)) = node.children.split_last() else {
    return false;
  };
  let Some(operation) = single_child(operations) else {
    return false;
  };
  if !is_simple_value_or_projection(returned) {
    return false;
  }
  let mutation = peel_transparent_single_child(operation);
  // Assignment setters (`self.f = v; self`) and simple method mutations
  // (`self.f.push(v); self`) are one rule: the language forces the shape
  // either way. Closure-bearing mutations stay reportable via the
  // value-plumbing test.
  matches!(mutation.kind, NodeKind::Assign | NodeKind::MethodCall) && mutation.children.iter().all(is_value_plumbing_expr)
}

/// A single method call forwarding simple values (`self.a(self.b)`).
fn is_forwarding_accessor_body(node: &NormalizedNode) -> bool {
  matches!(node.kind, NodeKind::MethodCall) && children_are_simple_values_or_projections(node)
}

/// A bare boolean combination of simple projections
/// (`ch == '_' || ch.is_ascii_alphanumeric()`).
fn is_trivial_boolean_projection(node: &NormalizedNode) -> bool {
  matches!(node.kind, NodeKind::BinaryOp(operator) if !is_reportable_binary_op(operator))
    && node
      .children
      .iter()
      .all(|child| is_simple_value_or_projection(child) || is_forwarding_accessor_body(child) || is_trivial_boolean_projection(child))
}

#[cfg(test)]
mod tests {
  use strict_test_support::TestFailure;
  use strict_test_support::ensure;
  use strict_test_support::ensure_eq;

  use super::SubUnit;
  use super::classify_closure_body;
  use super::classify_sub_unit;
  use super::classify_top_level_body;
  use super::extract_sub_units;
  use crate::code_unit::CodeUnitKind;
  use crate::fingerprint::Fingerprint;
  use crate::node::BinOpKind;
  use crate::node::LiteralKind;
  use crate::node::NodeKind;
  use crate::node::NormalizedNode;
  use crate::node::PlaceholderKind;
  use crate::suppression::RuleId;
  use crate::suppression::SuppressionPolicy;

  /// Enable every registered rule for boundary examples.
  fn policy() -> SuppressionPolicy {
    SuppressionPolicy::default()
  }

  /// Construct a variable placeholder with a chosen source identity.
  fn variable(index: usize) -> NormalizedNode {
    NormalizedNode::leaf(NodeKind::Placeholder(PlaceholderKind::Variable, index))
  }

  /// Construct an integer-literal node without a source value.
  fn literal_int() -> NormalizedNode {
    NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Int))
  }

  /// Construct a statement block from its ordered body.
  fn block(children: Vec<NormalizedNode>) -> NormalizedNode {
    NormalizedNode::with_children(NodeKind::Block, children)
  }

  /// Construct an operator with its left and right operands.
  fn binary(operator: BinOpKind, left: NormalizedNode, right: NormalizedNode) -> NormalizedNode {
    NormalizedNode::with_children(NodeKind::BinaryOp(operator), vec![left, right])
  }

  #[test]
  fn reportable_sub_unit_rejects_placeholder_only_blocks() -> Result<(), TestFailure> {
    ensure(
      classify_sub_unit(&block(vec![variable(0)]), &policy()) == Some(RuleId::SubNoStructure),
      "a bare placeholder has no standalone behavior",
    )
  }

  #[test]
  fn reportable_sub_unit_rejects_simple_predicates() -> Result<(), TestFailure> {
    let field_access = NormalizedNode::with_children(NodeKind::FieldAccess, vec![variable(0), variable(1)]);
    let predicate = binary(BinOpKind::Eq, field_access, variable(2));

    // Bare comparisons of simple values carry no reportable structure at
    // all, so the no-structure rule fires before the trivial-predicate
    // arm (which only applies to structured comparisons).
    ensure(
      classify_sub_unit(&predicate, &policy()) == Some(RuleId::SubNoStructure),
      "simple comparisons have no reportable structure",
    )?;
    ensure(
      classify_sub_unit(&block(vec![predicate]), &policy()) == Some(RuleId::SubNoStructure),
      "a transparent block preserves comparison classification",
    )
  }

  #[test]
  fn reportable_sub_unit_keeps_arithmetic_branch_body() -> Result<(), TestFailure> {
    let arithmetic = block(vec![binary(BinOpKind::Add, variable(0), literal_int())]);

    ensure(
      classify_sub_unit(&arithmetic, &policy()).is_none(),
      "arithmetic branches remain visible",
    )
  }

  #[test]
  fn reportable_sub_unit_keeps_binding_branch_body() -> Result<(), TestFailure> {
    let binding = NormalizedNode::with_children(NodeKind::LetBinding, vec![
      variable(0),
      NormalizedNode::none(),
      literal_int(),
      NormalizedNode::none(),
    ]);

    ensure(
      classify_sub_unit(&block(vec![binding]), &policy()).is_none(),
      "binding branches remain visible",
    )
  }

  #[test]
  fn direct_extraction_still_respects_only_node_threshold() -> Result<(), TestFailure> {
    let body = NormalizedNode::with_children(NodeKind::If, vec![variable(0), block(vec![variable(1)]), NormalizedNode::none()]);

    let sub_units = extract_sub_units(&body, 1);

    let expected = SubUnit {
      kind:         CodeUnitKind::IfBranch,
      node:         block(vec![variable(0)]),
      node_count:   2,
      description:  "if-then branch".to_owned(),
      suppressed:   None,
      parent_chain: None,
    };
    ensure(
      sub_units == vec![expected],
      "extraction retains and reindexes even a low-information branch",
    )?;
    for unit in sub_units {
      ensure(
        classify_sub_unit(&unit.node, &policy()) == Some(RuleId::SubNoStructure),
        "presentation classifies the retained branch",
      )?;
    }
    ensure(
      extract_sub_units(&body, 3).is_empty(),
      "the node floor excludes an undersized branch",
    )
  }

  /// Construct a call with its callee followed by its arguments.
  fn call(children: Vec<NormalizedNode>) -> NormalizedNode {
    NormalizedNode::with_children(NodeKind::Call, children)
  }

  #[test]
  fn reportable_sub_unit_rejects_forwarding_call_bodies() -> Result<(), TestFailure> {
    // `normalize_pat(&p.inner, ctx)`-style delegation: a call whose
    // arguments are all simple projections or placeholders.
    let field_access = NormalizedNode::with_children(NodeKind::FieldAccess, vec![variable(0), variable(1)]);
    let reference = NormalizedNode::with_children(
      NodeKind::Reference {
        mutable: false
      },
      vec![field_access],
    );
    let forwarding = call(vec![NormalizedNode::leaf(NodeKind::Path), reference, variable(2)]);

    ensure(
      classify_sub_unit(&forwarding, &policy()) == Some(RuleId::SubValuePlumbing),
      "a forwarding call is value plumbing",
    )?;
    ensure(
      classify_sub_unit(&block(vec![forwarding]), &policy()) == Some(RuleId::SubValuePlumbing),
      "a transparent block preserves forwarding classification",
    )
  }

  #[test]
  fn reportable_sub_unit_keeps_structured_constructor_bodies() -> Result<(), TestFailure> {
    // `NormalizedNode::with_children(kind, items.iter().map(...).collect())`
    // carries a nested closure pipeline and stays reportable.
    let closure = NormalizedNode::with_children(NodeKind::Closure, vec![variable(0)]);
    let map_call = NormalizedNode::with_children(NodeKind::MethodCall, vec![variable(1), closure]);
    let collect_call = NormalizedNode::with_children(NodeKind::MethodCall, vec![map_call]);
    let constructor = call(vec![
      NormalizedNode::leaf(NodeKind::Path),
      NormalizedNode::leaf(NodeKind::Path),
      collect_call,
    ]);

    ensure(
      classify_sub_unit(&constructor, &policy()).is_none(),
      "constructors with callback pipelines remain visible",
    )
  }

  /// Construct a method call from its receiver, method, and arguments.
  fn method_call(children: Vec<NormalizedNode>) -> NormalizedNode {
    NormalizedNode::with_children(NodeKind::MethodCall, children)
  }

  /// Wrap an expression in a terminated statement.
  fn semi(child: NormalizedNode) -> NormalizedNode {
    NormalizedNode::with_children(NodeKind::Semi, vec![child])
  }

  #[test]
  fn guard_returns_of_empty_defaults_are_not_reported() -> Result<(), TestFailure> {
    // `if shorted { return Vec::new(); }`-style bail-out guards.
    let empty_default = call(vec![NormalizedNode::leaf(NodeKind::Path)]);
    let guard = block(vec![semi(NormalizedNode::with_children(NodeKind::Return, vec![empty_default]))]);

    ensure(
      classify_sub_unit(&guard, &policy()) == Some(RuleId::SubEmptyDefaultReturn),
      "a guard returning empty construction is attributed to its rule",
    )
  }

  #[test]
  fn guard_returns_wrapping_values_stay_reported() -> Result<(), TestFailure> {
    // `if !text.is_empty() { return Some(text); }` stays a reportable
    // shape: the return carries a constructed value, not a bare default.
    let some_value = call(vec![NormalizedNode::leaf(NodeKind::Path), variable(0)]);
    let guard = block(vec![semi(NormalizedNode::with_children(NodeKind::Return, vec![some_value]))]);

    ensure(
      classify_sub_unit(&guard, &policy()).is_none(),
      "a guard returning a wrapped value remains visible",
    )
  }

  #[test]
  fn computed_returns_stay_reported() -> Result<(), TestFailure> {
    let computed = NormalizedNode::with_children(NodeKind::Return, vec![binary(BinOpKind::Add, variable(0), variable(1))]);

    ensure(
      classify_sub_unit(&block(vec![semi(computed)]), &policy()).is_none(),
      "a computed return remains visible through statement wrappers",
    )
  }

  #[test]
  fn error_returns_with_payloads_stay_reported() -> Result<(), TestFailure> {
    let error_value = call(vec![NormalizedNode::leaf(NodeKind::Path), variable(0)]);
    let return_error = NormalizedNode::with_children(NodeKind::Return, vec![error_value]);

    ensure(
      classify_sub_unit(&block(vec![semi(return_error)]), &policy()).is_none(),
      "a return carrying an error payload remains visible",
    )
  }

  #[test]
  fn plumbing_dispatch_return_is_tagged_value_plumbing() -> Result<(), TestFailure> {
    // `return normalize_if(node, source, mapping, ctx)`: one call with a
    // callee and >= 2 plumbing arguments is dispatch, not logic.
    let dispatch = call(vec![
      NormalizedNode::leaf(NodeKind::Path),
      variable(0),
      variable(1),
      variable(2),
      variable(3),
    ]);
    let body = block(vec![semi(NormalizedNode::with_children(NodeKind::Return, vec![dispatch]))]);

    ensure(
      classify_sub_unit(&body, &policy()) == Some(RuleId::SubValuePlumbing),
      "a dispatch call forwarding at least two arguments is value plumbing",
    )
  }

  #[test]
  fn return_some_value_stays_reportable() -> Result<(), TestFailure> {
    // `return Some(x)`: a two-child call (callee + one argument) is a
    // wrapped value, never dispatch plumbing.
    let some_value = call(vec![NormalizedNode::leaf(NodeKind::Path), variable(0)]);
    let wrapped = NormalizedNode::with_children(NodeKind::Return, vec![some_value]);

    ensure(
      classify_sub_unit(&wrapped, &policy()).is_none(),
      "a single wrapped argument does not become dispatch plumbing",
    )
  }

  #[test]
  fn return_with_computed_argument_stays_reportable() -> Result<(), TestFailure> {
    // `return f(a + b, c)`: a computed argument makes the call logic,
    // however many arguments it forwards.
    let computed_argument = binary(BinOpKind::Add, variable(0), variable(1));
    let dispatch = call(vec![NormalizedNode::leaf(NodeKind::Path), computed_argument, variable(2)]);
    let body = NormalizedNode::with_children(NodeKind::Return, vec![dispatch]);

    ensure(
      classify_sub_unit(&body, &policy()).is_none(),
      "computed dispatch arguments remain visible",
    )
  }

  #[test]
  fn message_only_macro_branches_are_not_reported() -> Result<(), TestFailure> {
    // `{ writeln!(writer, "No stale entries found.")?; }`
    let message = NormalizedNode::with_children(
      NodeKind::MacroCall {
        name: "writeln".to_owned(),
      },
      vec![variable(0), NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Str))],
    );
    let branch = block(vec![semi(NormalizedNode::with_children(NodeKind::Try, vec![message]))]);

    ensure(
      classify_sub_unit(&branch, &policy()) == Some(RuleId::SubMessageOnlyMacro),
      "message-only macros retain their suppression attribution",
    )
  }

  #[test]
  fn assertion_macro_branches_stay_reported() -> Result<(), TestFailure> {
    let oracle = NormalizedNode::with_children(
      NodeKind::MacroCall {
        name: "assert_eq".to_owned(),
      },
      vec![variable(0), variable(1)],
    );

    ensure(
      classify_sub_unit(&block(vec![semi(oracle)]), &policy()).is_none(),
      "assertion macros encode observable invariants",
    )
  }

  #[test]
  fn panic_macro_branches_stay_reported() -> Result<(), TestFailure> {
    let panic_expression = NormalizedNode::with_children(
      NodeKind::MacroCall {
        name: "panic".to_owned()
      },
      vec![NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Str))],
    );

    ensure(
      classify_sub_unit(&block(vec![semi(panic_expression)]), &policy()).is_none(),
      "panic expressions remain visible detector input",
    )
  }

  #[test]
  fn constructor_dispatch_arms_are_not_reported() -> Result<(), TestFailure> {
    // `Language::Rust => Box::new(RustAnalyzer::new())`
    let new_call = call(vec![NormalizedNode::leaf(NodeKind::Path)]);
    let dispatch = call(vec![NormalizedNode::leaf(NodeKind::Path), new_call]);

    ensure(
      classify_sub_unit(&dispatch, &policy()) == Some(RuleId::SubValuePlumbing),
      "nested constructor dispatch is value plumbing",
    )
  }

  #[test]
  fn constructor_assembly_arms_are_not_reported() -> Result<(), TestFailure> {
    // `NormalizedNode::with_children(KIND, vec![norm(a), norm(b)])`
    let assembly = call(vec![
      NormalizedNode::leaf(NodeKind::Path),
      NormalizedNode::leaf(NodeKind::Path),
      NormalizedNode::with_children(
        NodeKind::MacroCall {
          name: "vec".to_owned()
        },
        vec![call(vec![variable(0), variable(1)]), call(vec![variable(0), variable(2)])],
      ),
    ]);

    ensure(
      classify_sub_unit(&assembly, &policy()) == Some(RuleId::SubValuePlumbing),
      "assembling simple constructor values is value plumbing",
    )
  }

  #[test]
  fn collection_mutation_branches_are_not_reported() -> Result<(), TestFailure> {
    // `{ files.push(path.to_path_buf()); }`
    let projection = method_call(vec![variable(0), variable(1)]);
    let push = method_call(vec![variable(2), variable(3), projection]);

    ensure(
      classify_sub_unit(&block(vec![semi(push)]), &policy()) == Some(RuleId::SubValuePlumbing),
      "a collection mutation forwarding simple projections is value plumbing",
    )
  }

  #[test]
  fn projection_only_method_predicates_are_not_reported() -> Result<(), TestFailure> {
    // `node.children.iter().any(is_simple_value_or_projection)`
    let field = NormalizedNode::with_children(NodeKind::FieldAccess, vec![variable(0), variable(1)]);
    let iterator = method_call(vec![field, variable(2)]);
    let predicate = method_call(vec![iterator, variable(3), variable(4)]);

    ensure(
      classify_sub_unit(&predicate, &policy()) == Some(RuleId::SubValuePlumbing),
      "a projection-only method chain is value plumbing",
    )
  }

  #[test]
  fn value_plumbing_with_nested_closures_stays_reported() -> Result<(), TestFailure> {
    let callback = NormalizedNode::with_children(NodeKind::Closure, vec![binary(BinOpKind::Add, variable(0), literal_int())]);
    let pipeline = method_call(vec![variable(1), variable(2), callback]);

    ensure(
      classify_sub_unit(&block(vec![pipeline]), &policy()).is_none(),
      "nested callback computation keeps a chain visible",
    )
  }

  #[test]
  fn top_level_builder_setters_are_not_reportable() -> Result<(), TestFailure> {
    // `self.kind_resolver = Some(resolver); self`
    let assign = NormalizedNode::with_children(NodeKind::Assign, vec![
      NormalizedNode::with_children(NodeKind::FieldAccess, vec![variable(0), variable(1)]),
      call(vec![NormalizedNode::leaf(NodeKind::Path), variable(2)]),
    ]);
    let body = block(vec![semi(assign), variable(0)]);

    ensure(
      classify_top_level_body(&body, &policy()) == Some(RuleId::AstSetterReturningSelf),
      "a setter followed by self receives the setter rule",
    )
  }

  #[test]
  fn top_level_accessor_forwarding_is_not_reportable() -> Result<(), TestFailure> {
    // `self.percent_of_total(self.exact_duplicate_lines)`
    let projection = NormalizedNode::with_children(NodeKind::FieldAccess, vec![variable(0), variable(1)]);
    let body = method_call(vec![variable(0), variable(2), projection]);

    ensure(
      classify_top_level_body(&block(vec![body]), &policy()) == Some(RuleId::AstForwardingAccessor),
      "simple accessor forwarding receives the accessor rule",
    )
  }

  #[test]
  fn top_level_boolean_projections_are_not_reportable() -> Result<(), TestFailure> {
    // `ch == '_' || ch.is_ascii_alphanumeric()`
    let equality = binary(BinOpKind::Eq, variable(0), literal_int());
    let predicate_call = method_call(vec![variable(0), variable(1)]);
    let body = binary(BinOpKind::Or, equality, predicate_call);

    ensure(
      classify_top_level_body(&block(vec![body]), &policy()) == Some(RuleId::AstBooleanProjection),
      "a simple boolean combination receives the projection rule",
    )
  }

  #[test]
  fn top_level_constant_binding_wrappers_stay_reportable() -> Result<(), TestFailure> {
    // `fixture_path("cargo-dupes", name)`: a Call-rooted wrapper that
    // binds a constant is a deliberate named specialization.
    let body = call(vec![
      variable(0),
      NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Str)),
      variable(1),
    ]);

    ensure(
      classify_top_level_body(&block(vec![body]), &policy()).is_none(),
      "top-level call wrappers remain visible",
    )
  }

  #[test]
  fn top_level_struct_constructors_stay_reportable() -> Result<(), TestFailure> {
    // `Self { root }`
    let field = NormalizedNode::with_children(NodeKind::FieldValue, vec![variable(0), variable(0)]);
    let init = NormalizedNode::with_children(NodeKind::StructInit, vec![NormalizedNode::none(), field]);

    ensure(
      classify_top_level_body(&block(vec![init]), &policy()).is_none(),
      "top-level struct construction remains visible",
    )
  }

  #[test]
  fn closure_comparator_adapters_are_not_reportable() -> Result<(), TestFailure> {
    // `|| group_start_key(a).cmp(&group_start_key(b))`
    let first_key = call(vec![variable(0), variable(1)]);
    let second_key = call(vec![variable(0), variable(2)]);
    let comparison = method_call(vec![
      first_key,
      variable(3),
      NormalizedNode::with_children(
        NodeKind::Reference {
          mutable: false
        },
        vec![second_key],
      ),
    ]);

    ensure(
      classify_closure_body(&comparison, &policy()) == Some(RuleId::AstComparatorAdapter),
      "call-based comparator closures receive the comparator rule",
    )
  }

  #[test]
  fn closures_with_callback_pipelines_stay_reportable() -> Result<(), TestFailure> {
    // `path.segments.iter().map(|s| s.ident.to_string()).join("::")`:
    // the inner closure carries logic, so the chain stays reportable.
    let projection = NormalizedNode::with_children(NodeKind::FieldAccess, vec![variable(0), variable(1)]);
    let inner_closure = NormalizedNode::with_children(NodeKind::Closure, vec![method_call(vec![projection, variable(2)])]);
    let chain = method_call(vec![method_call(vec![variable(3), variable(4)]), variable(5), inner_closure]);

    ensure(
      classify_closure_body(&block(vec![chain.clone()]), &policy()).is_none(),
      "callback-bearing closures remain visible",
    )?;
    ensure(
      classify_sub_unit(&block(vec![chain]), &policy()).is_none(),
      "the same callback chain remains visible as a sub-unit",
    )
  }

  /// Construct an if-guarded assignment using distinct source placeholders.
  fn setter_if(target: usize, value: usize) -> NormalizedNode {
    let assign = NormalizedNode::with_children(NodeKind::Assign, vec![variable(target), variable(value)]);
    NormalizedNode::with_children(NodeKind::If, vec![
      binary(BinOpKind::Gt, variable(value), literal_int()),
      block(vec![assign]),
      NormalizedNode::none(),
    ])
  }

  /// Expected canonical assignment branch, optionally linked to an owning chain.
  fn assignment_branch(parent_chain: Option<Fingerprint>) -> SubUnit {
    SubUnit {
      kind: CodeUnitKind::IfBranch,
      node: block(vec![NormalizedNode::with_children(NodeKind::Assign, vec![
        variable(0),
        variable(1),
      ])]),
      node_count: 4,
      description: "if-then branch".to_owned(),
      suppressed: None,
      parent_chain,
    }
  }

  /// Retain the complete extraction scenario when its canonical units differ.
  #[derive(Debug, thiserror::Error)]
  #[error(
    "sub-unit extraction expectation failed: {source}; body: {body:?}; minimum: {minimum}; expected: {expected:?}; actual: {actual:?}"
  )]
  struct ExtractionTestFailure {
    /// Original normalized function body before canonical reindexing.
    body:     NormalizedNode,
    /// Node-count floor supplied to extraction.
    minimum:  usize,
    /// Independently specified units, in extraction order.
    expected: Vec<SubUnit>,
    /// Complete extracted population and its ownership metadata.
    actual:   Vec<SubUnit>,
    /// Native assertion failure.
    source:   TestFailure,
  }

  /// Check complete canonical units without projecting away body or chain evidence.
  fn check_extracted_units(body: NormalizedNode, minimum: usize, expected: Vec<SubUnit>) -> Result<(), Box<ExtractionTestFailure>> {
    let actual = extract_sub_units(&body, minimum);
    ensure(
      actual == expected,
      "extraction preserves exact canonical bodies, ordering, and chain ownership",
    )
    .map_err(|source| {
      Box::new(ExtractionTestFailure {
        body,
        minimum,
        expected,
        actual,
        source,
      })
    })
  }

  #[test]
  fn consecutive_setter_ifs_extract_as_one_chain() -> Result<(), TestFailure> {
    let body = block(vec![setter_if(0, 1), setter_if(2, 3), setter_if(4, 5)]);

    let sub_units = extract_sub_units(&body, 1);

    let chains: Vec<_> = sub_units.iter().filter(|unit| unit.kind == CodeUnitKind::IfChain).collect();
    ensure_eq(&chains.len(), &1, "consecutive setters form one chain")?;
    let branches: Vec<_> = sub_units.iter().filter(|unit| unit.kind == CodeUnitKind::IfBranch).collect();
    ensure_eq(&branches.len(), &3, "chained branches stay extracted, linked to their owning chain")?;
    for chain in chains {
      ensure_eq(
        &chain.description.as_str(),
        &"if chain (3 branches)",
        "the chain describes its complete membership",
      )?;
      let chain_fingerprint = Fingerprint::from_node(&chain.node);
      for branch in &branches {
        ensure(
          branch.parent_chain == Some(chain_fingerprint),
          "each branch retains its owning chain identity",
        )?;
      }
      ensure(
        classify_sub_unit(&chain.node, &policy()).is_none(),
        "the complete assignment chain is reportable",
      )?;
    }
    Ok(())
  }

  #[test]
  fn separated_if_chains_keep_distinct_owners_and_extraction_order() -> Result<(), Box<ExtractionTestFailure>> {
    let body = block(vec![
      semi(setter_if(0, 1)),
      semi(setter_if(2, 3)),
      literal_int(),
      setter_if(4, 5),
      setter_if(6, 7),
      setter_if(8, 9),
    ]);
    let first_chain = block(vec![setter_if(1, 0), setter_if(3, 2)]);
    let second_chain = block(vec![setter_if(1, 0), setter_if(3, 2), setter_if(5, 4)]);
    let first_fingerprint = Fingerprint::from_node(&first_chain);
    let second_fingerprint = Fingerprint::from_node(&second_chain);
    let mut expected = vec![
      SubUnit {
        kind:         CodeUnitKind::IfChain,
        node:         first_chain,
        node_count:   17,
        description:  "if chain (2 branches)".to_owned(),
        suppressed:   None,
        parent_chain: None,
      },
      SubUnit {
        kind:         CodeUnitKind::IfChain,
        node:         second_chain,
        node_count:   25,
        description:  "if chain (3 branches)".to_owned(),
        suppressed:   None,
        parent_chain: None,
      },
    ];
    for owner in [
      first_fingerprint, first_fingerprint, second_fingerprint, second_fingerprint, second_fingerprint,
    ] {
      expected.push(assignment_branch(Some(owner)));
    }
    check_extracted_units(body, 1, expected)
  }

  #[test]
  fn multi_child_statement_wrappers_do_not_create_if_chains() -> Result<(), Box<ExtractionTestFailure>> {
    let body = block(vec![
      NormalizedNode::with_children(NodeKind::Semi, vec![setter_if(0, 1), literal_int()]),
      setter_if(2, 3),
    ]);
    check_extracted_units(body, 1, vec![assignment_branch(None), assignment_branch(None)])
  }

  #[test]
  fn single_if_statement_still_extracts_branch_not_chain() -> Result<(), Box<ExtractionTestFailure>> {
    let body = block(vec![setter_if(0, 1)]);
    check_extracted_units(body, 1, vec![assignment_branch(None)])
  }

  #[test]
  fn chain_members_still_extract_nested_structures() -> Result<(), TestFailure> {
    let inner_loop = NormalizedNode::with_children(NodeKind::While, vec![
      binary(BinOpKind::Gt, variable(0), literal_int()),
      block(vec![binary(BinOpKind::Add, variable(1), literal_int())]),
    ]);
    let if_with_loop = NormalizedNode::with_children(NodeKind::If, vec![
      binary(BinOpKind::Gt, variable(0), literal_int()),
      block(vec![inner_loop]),
      NormalizedNode::none(),
    ]);
    let body = block(vec![if_with_loop, setter_if(2, 3)]);

    let sub_units = extract_sub_units(&body, 1);

    ensure(
      sub_units.iter().any(|unit| unit.kind == CodeUnitKind::IfChain),
      "consecutive conditional statements retain their chain",
    )?;
    ensure(
      sub_units.iter().any(|unit| unit.kind == CodeUnitKind::LoopBody),
      "structures nested inside chain branches are still extracted",
    )
  }
}
