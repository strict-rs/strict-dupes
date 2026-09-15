//! Tree-sitter node normalization.
//!
//! Converts tree-sitter CST nodes into `dupes-core` [`NormalizedNode`] trees
//! using a table-driven [`NodeMapping`]. The primary entry point is
//! [`normalize_ts_node`].

use std::collections::HashMap;
use std::mem;
use std::str;
use std::str::Utf8Error;

use dupes_core::node::BinOpKind;
use dupes_core::node::NodeKind;
use dupes_core::node::NormalizationContext;
use dupes_core::node::NormalizedNode;
use dupes_core::node::PlaceholderKind;
use dupes_core::node::UnOpKind;

use crate::mapping::NodeMapping;

/// A failed text read from the byte range reported by a native syntax node.
#[derive(Debug, thiserror::Error)]
pub enum NodeTextError {
  /// The native node's byte range does not belong to the supplied input.
  #[error("node range {range:?} is outside the supplied {} bytes", input.len())]
  OutOfBounds {
    /// Complete byte input supplied to normalization or extraction.
    input: Vec<u8>,
    /// Original native byte and point range requested by the read.
    range: tree_sitter::Range,
  },
  /// The selected node bytes are not valid UTF-8 text.
  #[error("node text at {range:?} is not UTF-8: {source}")]
  Utf8 {
    /// Complete byte input, including the undecodable node bytes.
    input:  Vec<u8>,
    /// Original native byte and point range selected for decoding.
    range:  tree_sitter::Range,
    /// Native UTF-8 failure relative to the selected node's byte slice.
    source: Utf8Error,
  },
}

/// Normalization failure with every completed child at each interrupted parent.
#[derive(Debug, thiserror::Error)]
pub enum NormalizationError {
  /// Required identifier or operator text could not be read.
  #[error(transparent)]
  Text(#[from] NodeTextError),
  /// A child failed after earlier children had already been normalized.
  #[error("normalizing children of {kind} at {range:?} failed: {source}")]
  Children {
    /// Native grammar kind of the interrupted parent.
    kind:      String,
    /// Native byte and point range of that parent.
    range:     tree_sitter::Range,
    /// Complete normalized children produced before the failure, in order.
    completed: Vec<NormalizedNode>,
    /// Original failure from the interrupted child.
    source:    Box<Self>,
  },
}

/// Normalize a tree-sitter node into a `NormalizedNode` using the provided mapping.
///
/// The mapping table drives classification of tree-sitter node kinds into
/// the dupes-core normalized representation. Unknown named nodes are recursively
/// normalized and wrapped in a `Block`.
///
/// # Errors
///
/// Returns unreadable identifier or operator text with its complete byte input,
/// native range and cause, and any children completed before that failure.
pub fn normalize_ts_node(
  node: &tree_sitter::Node<'_>,
  source: &[u8],
  mapping: &NodeMapping,
  context: &mut NormalizationContext,
) -> Result<NormalizedNode, NormalizationError> {
  let kind = node.kind();

  // 1. Kinds that normalize to Opaque: parse errors, configured skips (a safety net when called
  //    directly), and configured opaque kinds.
  if node.is_error() || node.is_missing() || mapping.skip_kinds.contains(kind) || mapping.opaque_kinds.contains(kind) {
    return Ok(NormalizedNode::leaf(NodeKind::Opaque));
  }

  // 2. Identifiers → Placeholder
  if mapping.identifier_kinds.contains(kind) {
    let text = node_text(node, source)?;
    let index = context.placeholder(text, PlaceholderKind::Variable);
    return Ok(NormalizedNode::leaf(NodeKind::Placeholder(PlaceholderKind::Variable, index)));
  }

  // 3. Literals → Literal(kind)
  if let Some(literal_kind) = mapping.literal_kinds.get(kind) {
    return Ok(NormalizedNode::leaf(NodeKind::Literal(*literal_kind)));
  }

  // 4. Direct node-kind-to-NodeKind mappings
  if let Some(mapped_kind) = mapping.node_kinds.get(kind) {
    let children = normalize_named_children(node, source, mapping, context)?;
    return Ok(NormalizedNode::with_children(mapped_kind.clone(), children));
  }

  // 5. Structural kinds

  // If/conditional
  if mapping.if_kinds.contains(kind) {
    return normalize_if(node, source, mapping, context);
  }

  // For loop
  if mapping.for_kinds.contains(kind) {
    return normalize_for(node, source, mapping, context);
  }

  // While loop
  if mapping.while_kinds.contains(kind) {
    return normalize_while(node, source, mapping, context);
  }

  // Infinite loop
  if mapping.loop_kinds.contains(kind) {
    return normalize_fields(node, &["body"], NodeKind::Loop, source, mapping, context);
  }

  // Match/switch
  if mapping.match_kinds.contains(kind) {
    return normalize_match(node, source, mapping, context);
  }

  // Call
  if mapping.call_kinds.contains(kind) {
    return normalize_call(node, source, mapping, context);
  }

  // Return
  if mapping.return_kinds.contains(kind) {
    return normalize_return(node, source, mapping, context);
  }

  // Block
  if mapping.block_kinds.contains(kind) {
    return normalize_as_block(node, source, mapping, context);
  }

  // Assignment
  if mapping.assignment_kinds.contains(kind) {
    return normalize_assignment(node, source, mapping, context);
  }

  // Function definitions (nested)
  if mapping.function_def_kinds.contains(kind) {
    return normalize_as_block(node, source, mapping, context);
  }

  // 6. Binary/unary expressions — driven by mapping
  if mapping.binary_op_kinds.contains(kind) {
    return normalize_binary_op(node, source, mapping, context);
  }

  if mapping.unary_op_kinds.contains(kind) {
    return normalize_unary_op(node, source, mapping, context);
  }

  // 7. Anonymous nodes → skip (shouldn't reach here normally)
  if !node.is_named() {
    return Ok(NormalizedNode::leaf(NodeKind::Opaque));
  }

  // 8. Unknown named nodes → recursively normalize children, wrap in Block
  let children = normalize_named_children(node, source, mapping, context)?;
  if children.is_empty() {
    return Ok(NormalizedNode::leaf(NodeKind::Opaque));
  }
  match <[NormalizedNode; 1]>::try_from(children) {
    Ok([child]) => Ok(child),
    Err(multiple_children) => Ok(NormalizedNode::with_children(NodeKind::Block, multiple_children)),
  }
}

/// Normalize all named children of a node, skipping those in `skip_kinds`.
pub(crate) fn normalize_named_children(
  node: &tree_sitter::Node<'_>,
  source: &[u8],
  mapping: &NodeMapping,
  context: &mut NormalizationContext,
) -> Result<Vec<NormalizedNode>, NormalizationError> {
  let mut cursor = node.walk();
  let children = node
    .named_children(&mut cursor)
    .filter(|child| !mapping.skip_kinds.contains(child.kind()))
    .map(Some);
  normalize_selected_children(node, children, source, mapping, context)
}

/// Normalize a node's named children and wrap them in a `Block`.
fn normalize_as_block(
  node: &tree_sitter::Node<'_>,
  source: &[u8],
  mapping: &NodeMapping,
  context: &mut NormalizationContext,
) -> Result<NormalizedNode, NormalizationError> {
  Ok(NormalizedNode::with_children(
    NodeKind::Block,
    normalize_named_children(node, source, mapping, context)?,
  ))
}

/// Find the text of the first anonymous child (used for operator detection).
#[allow(
  clippy::single_call_fn,
  reason = "Operator selection owns the checked native text read before mapping an anonymous token"
)]
fn find_operator_text<'source>(node: &tree_sitter::Node<'_>, source: &'source [u8]) -> Result<Option<&'source str>, NodeTextError> {
  let cursor = &mut node.walk();
  for child in node.children(cursor) {
    if !child.is_named() {
      let text = node_text(&child, source)?;
      if !text.is_empty() {
        return Ok(Some(text));
      }
    }
  }
  Ok(None)
}

/// Map a node's operator text through an operator table, with a fallback.
fn lookup_operator_kind<Value: Clone>(
  node: &tree_sitter::Node<'_>,
  source: &[u8],
  map: &HashMap<&'static str, Value>,
  fallback: Value,
) -> Result<Value, NodeTextError> {
  Ok(
    find_operator_text(node, source)?
      .and_then(|text| map.get(text).cloned())
      .unwrap_or(fallback),
  )
}

/// Read exactly a native node's byte range without panicking or masking decoding failures.
pub(crate) fn node_text<'source>(node: &tree_sitter::Node<'_>, source: &'source [u8]) -> Result<&'source str, NodeTextError> {
  let range = node.range();
  let bytes = node_bytes(node, source)?;
  str::from_utf8(bytes).map_err(|failure| NodeTextError::Utf8 {
    input: source.to_vec(),
    range,
    source: failure,
  })
}

/// Validate a native range before normalization or query predicates read its bytes.
pub(crate) fn node_bytes<'source>(node: &tree_sitter::Node<'_>, source: &'source [u8]) -> Result<&'source [u8], NodeTextError> {
  let range = node.range();
  source
    .get(range.start_byte..range.end_byte)
    .ok_or_else(|| NodeTextError::OutOfBounds {
      input: source.to_vec(),
      range,
    })
}

/// Preserve a completed prefix when the next child cannot be normalized.
fn append_normalized_child(
  parent: &tree_sitter::Node<'_>,
  children: &mut Vec<NormalizedNode>,
  outcome: Result<NormalizedNode, NormalizationError>,
) -> Result<(), NormalizationError> {
  match outcome {
    Ok(child) => {
      children.push(child);
      Ok(())
    }
    Err(source) => Err(NormalizationError::Children {
      kind:      parent.kind().to_owned(),
      range:     parent.range(),
      completed: mem::take(children),
      source:    Box::new(source),
    }),
  }
}

/// Normalize selected children in order, retaining explicit absent-field sentinels.
fn normalize_selected_children<'tree>(
  parent: &tree_sitter::Node<'tree>,
  selected: impl IntoIterator<Item = Option<tree_sitter::Node<'tree>>>,
  source: &[u8],
  mapping: &NodeMapping,
  context: &mut NormalizationContext,
) -> Result<Vec<NormalizedNode>, NormalizationError> {
  let mut children = Vec::new();
  for selected_child in selected {
    let outcome = selected_child.map_or_else(
      || Ok(NormalizedNode::none()),
      |child| normalize_ts_node(&child, source, mapping, context),
    );
    append_normalized_child(parent, &mut children, outcome)?;
  }
  Ok(children)
}

/// Normalize a construct's declared fields in the order required by its semantic kind.
fn normalize_fields(
  node: &tree_sitter::Node<'_>,
  fields: &[&str],
  kind: NodeKind,
  source: &[u8],
  mapping: &NodeMapping,
  context: &mut NormalizationContext,
) -> Result<NormalizedNode, NormalizationError> {
  let selected = fields.iter().map(|field| node.child_by_field_name(field));
  let children = normalize_selected_children(node, selected, source, mapping, context)?;
  Ok(NormalizedNode::with_children(kind, children))
}

/// Normalize an if/conditional construct.
/// Produces: [condition, `then_branch`, `else_or_None`]
#[allow(
  clippy::single_call_fn,
  reason = "Conditional normalization owns the condition, consequence, and absent-alternative slots"
)]
fn normalize_if(
  node: &tree_sitter::Node<'_>,
  source: &[u8],
  mapping: &NodeMapping,
  context: &mut NormalizationContext,
) -> Result<NormalizedNode, NormalizationError> {
  normalize_fields(
    node,
    &["condition", "consequence", "alternative"],
    NodeKind::If,
    source,
    mapping,
    context,
  )
}

/// Normalize a for-loop construct.
/// Produces: [pattern, iterable, body]
#[allow(
  clippy::single_call_fn,
  reason = "For-loop normalization fixes the binding, iterable, and body order"
)]
fn normalize_for(
  node: &tree_sitter::Node<'_>,
  source: &[u8],
  mapping: &NodeMapping,
  context: &mut NormalizationContext,
) -> Result<NormalizedNode, NormalizationError> {
  // Python uses "left" for pattern and "right" for iterable
  normalize_fields(node, &["left", "right", "body"], NodeKind::ForLoop, source, mapping, context)
}

/// Normalize a while-loop construct.
/// Produces: [condition, body]
#[allow(
  clippy::single_call_fn,
  reason = "While-loop normalization preserves the condition before its body"
)]
fn normalize_while(
  node: &tree_sitter::Node<'_>,
  source: &[u8],
  mapping: &NodeMapping,
  context: &mut NormalizationContext,
) -> Result<NormalizedNode, NormalizationError> {
  normalize_fields(node, &["condition", "body"], NodeKind::While, source, mapping, context)
}

/// Normalize a match/switch construct.
/// Produces: `[subject, arm0, arm1, ...]` where each arm is
/// `MatchArm [pattern, guard_or_None, body]` per dupes-core convention.
#[allow(
  clippy::single_call_fn,
  reason = "Match normalization owns ordered arms and preserves completed arms on failure"
)]
fn normalize_match(
  node: &tree_sitter::Node<'_>,
  source: &[u8],
  mapping: &NodeMapping,
  context: &mut NormalizationContext,
) -> Result<NormalizedNode, NormalizationError> {
  let mut children = normalize_selected_children(node, [node.child_by_field_name("subject")], source, mapping, context)?;

  // Collect match arms/cases using mapping-driven kind detection
  let cursor = &mut node.walk();
  for child in node.named_children(cursor) {
    if mapping.match_arm_kinds.contains(child.kind()) {
      let outcome = normalize_fields(
        &child,
        &["pattern", "guard", "consequence"],
        NodeKind::MatchArm,
        source,
        mapping,
        context,
      );
      append_normalized_child(node, &mut children, outcome)?;
    }
  }

  Ok(NormalizedNode::with_children(NodeKind::Match, children))
}

/// Normalize a function/method call.
/// Produces: [func, arg0, arg1, ...]
#[allow(
  clippy::single_call_fn,
  reason = "Call normalization retains the callee and completed argument prefix on failure"
)]
fn normalize_call(
  node: &tree_sitter::Node<'_>,
  source: &[u8],
  mapping: &NodeMapping,
  context: &mut NormalizationContext,
) -> Result<NormalizedNode, NormalizationError> {
  let mut children = normalize_selected_children(node, [node.child_by_field_name("function")], source, mapping, context)?;

  // Collect arguments
  if let Some(arguments) = node.child_by_field_name("arguments") {
    let cursor = &mut arguments.walk();
    for argument in arguments.named_children(cursor) {
      if !mapping.skip_kinds.contains(argument.kind()) {
        let outcome = normalize_ts_node(&argument, source, mapping, context);
        append_normalized_child(node, &mut children, outcome)?;
      }
    }
  }

  Ok(NormalizedNode::with_children(NodeKind::Call, children))
}

/// Normalize a return statement.
/// Produces: [] or [value]
#[allow(
  clippy::single_call_fn,
  reason = "Return normalization distinguishes an empty return from its normalized payload"
)]
fn normalize_return(
  node: &tree_sitter::Node<'_>,
  source: &[u8],
  mapping: &NodeMapping,
  context: &mut NormalizationContext,
) -> Result<NormalizedNode, NormalizationError> {
  let children = normalize_named_children(node, source, mapping, context)?;
  Ok(NormalizedNode::with_children(NodeKind::Return, children))
}

/// Normalize an assignment.
/// Produces: [target, value]
#[allow(
  clippy::single_call_fn,
  reason = "Assignment normalization fixes target-before-value ordering"
)]
fn normalize_assignment(
  node: &tree_sitter::Node<'_>,
  source: &[u8],
  mapping: &NodeMapping,
  context: &mut NormalizationContext,
) -> Result<NormalizedNode, NormalizationError> {
  normalize_fields(node, &["left", "right"], NodeKind::Assign, source, mapping, context)
}

/// Normalize a binary operation.
/// Produces: `BinaryOp(kind) [left, right]`.
///
/// Uses `left`/`right` field names first (e.g., `binary_operator`, `boolean_operator`).
/// Falls back to positional named children for nodes without field names
/// (e.g., Python `comparison_operator`).
#[allow(
  clippy::single_call_fn,
  reason = "Binary normalization owns positional comparison folding and partial-child evidence"
)]
fn normalize_binary_op(
  node: &tree_sitter::Node<'_>,
  source: &[u8],
  mapping: &NodeMapping,
  context: &mut NormalizationContext,
) -> Result<NormalizedNode, NormalizationError> {
  let operator_kind = lookup_operator_kind(node, source, &mapping.binary_op_map, BinOpKind::Other)?;

  // Try field-based access first (binary_operator, boolean_operator)
  let left_field = node.child_by_field_name("left");
  let right_field = node.child_by_field_name("right");

  let children = if let (Some(left), Some(right)) = (left_field, right_field) {
    normalize_selected_children(node, [Some(left), Some(right)], source, mapping, context)?
  } else {
    // Fall back to positional named children (e.g., Python comparison_operator
    // which uses positional children instead of left/right field names).
    // For chained comparisons (a < b < c), fold all operands into nested
    // BinaryOp nodes: BinaryOp(Lt, [a, BinaryOp(Lt, [b, c])])
    let cursor = &mut node.walk();
    let operands = normalize_selected_children(node, node.named_children(cursor).map(Some), source, mapping, context)?;
    // Fold from right: [a, b, c] → BinaryOp(op, [a, BinaryOp(op, [b, c])])
    let mut iter = operands.into_iter().rev();
    let Some(last) = iter.next() else {
      return Ok(NormalizedNode::with_children(NodeKind::BinaryOp(operator_kind), vec![
        NormalizedNode::none(),
        NormalizedNode::none(),
      ]));
    };
    let Some(previous) = iter.next() else {
      return Ok(NormalizedNode::with_children(NodeKind::BinaryOp(operator_kind), vec![
        last,
        NormalizedNode::none(),
      ]));
    };
    let combined = NormalizedNode::with_children(NodeKind::BinaryOp(operator_kind), vec![previous, last]);
    return Ok(iter.fold(combined, |suffix, operand| {
      NormalizedNode::with_children(NodeKind::BinaryOp(operator_kind), vec![operand, suffix])
    }));
  };

  Ok(NormalizedNode::with_children(NodeKind::BinaryOp(operator_kind), children))
}

/// Normalize a unary operation.
/// Produces: `UnaryOp(kind) [operand]`.
#[allow(
  clippy::single_call_fn,
  reason = "Unary normalization owns operator lookup and the grammar-dependent operand selection"
)]
fn normalize_unary_op(
  node: &tree_sitter::Node<'_>,
  source: &[u8],
  mapping: &NodeMapping,
  context: &mut NormalizationContext,
) -> Result<NormalizedNode, NormalizationError> {
  let operator_kind = lookup_operator_kind(node, source, &mapping.unary_op_map, UnOpKind::Other)?;

  let operand_node = node
    .child_by_field_name("argument")
    .or_else(|| node.child_by_field_name("operand"))
    .or_else(|| {
      let cursor = &mut node.walk();
      node.named_children(cursor).next()
    });
  let children = normalize_selected_children(node, [operand_node], source, mapping, context)?;

  Ok(NormalizedNode::with_children(NodeKind::UnaryOp(operator_kind), children))
}

#[cfg(test)]
mod tests {
  use dupes_core::node::BinOpKind;
  use dupes_core::node::LiteralKind;
  use dupes_core::node::NodeKind;
  use dupes_core::node::NormalizationContext;
  use dupes_core::node::NormalizedNode;
  use dupes_core::node::PlaceholderKind;
  use dupes_core::node::UnOpKind;
  use strict_test_support::ComparisonFailure;
  use strict_test_support::ConditionFailure;
  use strict_test_support::ensure;
  use strict_test_support::ensure_eq;

  use super::NodeTextError;
  use super::NormalizationError;
  use super::normalize_named_children;
  use super::normalize_ts_node;
  use crate::mapping::NodeMapping;

  /// Preserve parser setup failures and complete normalized expectation values.
  #[derive(Debug, thiserror::Error)]
  enum NormalizerTestFailure {
    /// The fixture grammar was rejected by the parser.
    #[error(transparent)]
    Language(#[from] tree_sitter::LanguageError),
    /// Required source text could not be normalized.
    #[error(transparent)]
    Normalization(#[from] NormalizationError),
    /// A fallible normalization attempt lost its expected evidence or context.
    #[error("{source}; normalization outcome: {outcome:?}; context: {context:?}; tree: {tree:?}")]
    FailureEvidence {
      /// Complete success or failure returned by the attempted normalization.
      outcome: Box<Result<NormalizedNode, NormalizationError>>,
      /// Placeholder assignments left available to the caller.
      context: Box<NormalizationContext>,
      /// Native tree used by the attempt.
      tree:    tree_sitter::Tree,
      /// Failed evidence-preservation expectation.
      source:  ConditionFailure,
    },
    /// Parsing returned no tree for the supplied fixture.
    #[error("the parser returned no tree for {input:?}")]
    NoTree {
      /// Complete source supplied to the parser.
      input: String,
    },
    /// A fixture did not contain the requested syntax node.
    #[error("fixture tree lacks {selection}: {tree:?}")]
    MissingNode {
      /// Native tree returned for the fixture.
      tree:      tree_sitter::Tree,
      /// Field or child selected by the test.
      selection: &'static str,
    },
    /// A normalized tree violated the expected semantic contract.
    #[error(transparent)]
    Normalized(#[from] Box<ComparisonFailure<NormalizedNode, NormalizedNode>>),
    /// Normalized children violated their complete sequence expectation.
    #[error(transparent)]
    Children(#[from] ComparisonFailure<Vec<NormalizedNode>, Vec<NormalizedNode>>),
    /// A malformed fixture did not preserve its native or normalized error signal.
    #[error("{source}; parse tree: {tree:?}; normalized tree: {normalized:?}")]
    Malformed {
      /// Native parse tree produced for the malformed source.
      tree:       tree_sitter::Tree,
      /// Complete normalized representation of that tree.
      normalized: Box<NormalizedNode>,
      /// Failed semantic expectation.
      source:     ConditionFailure,
    },
  }

  /// Build a Python-flavored mapping for normalizer unit tests.
  fn test_mapping() -> NodeMapping {
    NodeMapping::new()
      .identifiers(&["identifier"])
      .literals(&[
        ("integer", LiteralKind::Int),
        ("float", LiteralKind::Float),
        ("string", LiteralKind::Str),
        ("true", LiteralKind::Bool),
        ("false", LiteralKind::Bool),
      ])
      .binary_ops(&[
        ("+", BinOpKind::Add),
        ("-", BinOpKind::Sub),
        ("*", BinOpKind::Mul),
        ("==", BinOpKind::Eq),
        ("and", BinOpKind::And),
        ("or", BinOpKind::Or),
      ])
      .unary_ops(&[("not", UnOpKind::Not), ("-", UnOpKind::Neg)])
      .skip(&["comment", "decorator"])
      .opaque(&["type"])
      .blocks(&["block"])
      .calls(&["call"])
      .returns(&["return_statement"])
      .ifs(&["if_statement"])
      .for_loops(&["for_statement"])
      .while_loops(&["while_statement"])
      .matches(&["match_statement"])
      .assignments(&["assignment"])
      .function_defs(&["function_definition"])
      .binary_op_kinds(&["binary_operator", "boolean_operator", "comparison_operator"])
      .unary_op_kinds(&["not_operator", "unary_operator"])
      .match_arms(&["case_clause"])
  }

  /// Parse Python source and return the tree.
  fn parse(source: &str) -> Result<tree_sitter::Tree, NormalizerTestFailure> {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&tree_sitter_python::LANGUAGE.into())?;
    parser.parse(source, None).ok_or_else(|| NormalizerTestFailure::NoTree {
      input: source.to_owned()
    })
  }

  /// Get the first named child of the root (typically a statement).
  fn first_stmt(tree: &tree_sitter::Tree) -> Result<tree_sitter::Node<'_>, NormalizerTestFailure> {
    tree
      .root_node()
      .named_child(0)
      .ok_or_else(|| NormalizerTestFailure::MissingNode {
        tree:      tree.clone(),
        selection: "the first named statement",
      })
  }

  /// Select the expression inside the fixture's first expression statement.
  fn first_expression(tree: &tree_sitter::Tree) -> Result<tree_sitter::Node<'_>, NormalizerTestFailure> {
    first_stmt(tree)?
      .named_child(0)
      .ok_or_else(|| NormalizerTestFailure::MissingNode {
        tree:      tree.clone(),
        selection: "the first statement's expression",
      })
  }

  /// Construct an expected variable placeholder in encounter order.
  fn variable(index: usize) -> NormalizedNode {
    NormalizedNode::leaf(NodeKind::Placeholder(PlaceholderKind::Variable, index))
  }

  /// Check a fallible attempt while retaining its complete outcome and caller-owned context.
  fn check_attempt(
    tree: tree_sitter::Tree,
    mut context: NormalizationContext,
    outcome: Result<NormalizedNode, NormalizationError>,
    check: impl FnOnce(&Result<NormalizedNode, NormalizationError>, &mut NormalizationContext) -> Result<(), ConditionFailure>,
  ) -> Result<(), NormalizerTestFailure> {
    check(&outcome, &mut context).map_err(|source| NormalizerTestFailure::FailureEvidence {
      outcome: Box::new(outcome),
      context: Box::new(context),
      tree,
      source,
    })
  }

  /// Normalize a fixture's first statement through the real parser boundary.
  fn check_statement(source: &str, expected: NormalizedNode) -> Result<(), NormalizerTestFailure> {
    let tree = parse(source)?;
    let statement = first_stmt(&tree)?;
    let actual = normalize_ts_node(&statement, source.as_bytes(), &test_mapping(), &mut NormalizationContext::new())?;
    ensure_eq(actual, expected, "statement normalization preserves all kinds and ordered children")
      .map(drop)
      .map_err(Box::new)
      .map_err(NormalizerTestFailure::from)
  }

  /// Normalize all statements with one shared identifier context.
  fn check_statements(source: &str, mapping: &NodeMapping, expected: Vec<NormalizedNode>) -> Result<(), NormalizerTestFailure> {
    let tree = parse(source)?;
    let actual = normalize_named_children(&tree.root_node(), source.as_bytes(), mapping, &mut NormalizationContext::new())?;
    ensure_eq(actual, expected, "normalization preserves the complete ordered child sequence")
      .map(drop)
      .map_err(NormalizerTestFailure::from)
  }

  /// Normalize a function body without including its declaration's identifiers.
  fn check_function_body(source: &str, expected: Vec<NormalizedNode>) -> Result<(), NormalizerTestFailure> {
    let tree = parse(source)?;
    let body = first_stmt(&tree)?
      .child_by_field_name("body")
      .ok_or_else(|| NormalizerTestFailure::MissingNode {
        tree:      tree.clone(),
        selection: "the function body",
      })?;
    let actual = normalize_ts_node(&body, source.as_bytes(), &test_mapping(), &mut NormalizationContext::new())?;
    ensure_eq(
      actual,
      NormalizedNode::with_children(NodeKind::Block, expected),
      "function-body normalization retains every ordered child in its block",
    )
    .map(drop)
    .map_err(Box::new)
    .map_err(NormalizerTestFailure::from)
  }

  /// Detect an opaque subtree without depending on malformed grammar internals.
  fn has_opaque(node: &NormalizedNode) -> bool {
    node.kind == NodeKind::Opaque || node.children.iter().any(has_opaque)
  }

  /// Identifier and literal mapping entries drive actual normalization.
  #[test]
  fn node_kind_classification() -> Result<(), NormalizerTestFailure> {
    check_statements(
      "x\n42\n",
      &NodeMapping::new()
        .identifiers(&["identifier"])
        .literals(&[("integer", LiteralKind::Int)]),
      vec![variable(0), NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Int))],
    )
  }

  /// The first identifier starts the variable placeholder sequence.
  #[test]
  fn identifier_becomes_placeholder() -> Result<(), NormalizerTestFailure> {
    check_statement("x\n", variable(0))
  }

  /// Different identifiers receive distinct indices in source order.
  #[test]
  fn two_identifiers_get_different_indices() -> Result<(), NormalizerTestFailure> {
    check_statements("x\ny\n", &test_mapping(), vec![variable(0), variable(1)])
  }

  /// Repeated identifiers reuse their original indices.
  #[test]
  fn same_identifier_reuses_index() -> Result<(), NormalizerTestFailure> {
    check_statements("x\nx\n", &test_mapping(), vec![variable(0), variable(0)])
  }

  /// Integer syntax normalizes to the integer literal kind.
  #[test]
  fn integer_literal() -> Result<(), NormalizerTestFailure> {
    let source = "42\n";
    let tree = parse(source)?;
    let literal = first_stmt(&tree)?
      .named_child(0)
      .ok_or_else(|| NormalizerTestFailure::MissingNode {
        tree:      tree.clone(),
        selection: "the integer literal expression",
      })?;
    let actual = normalize_ts_node(&literal, source.as_bytes(), &test_mapping(), &mut NormalizationContext::new())?;
    ensure_eq(
      actual,
      NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Int)),
      "integer syntax normalizes to the complete integer literal node",
    )
    .map(drop)
    .map_err(Box::new)
    .map_err(NormalizerTestFailure::from)
  }

  /// String syntax remains distinct from numeric literals.
  #[test]
  fn string_literal() -> Result<(), NormalizerTestFailure> {
    check_statement("\"hello\"\n", NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Str)))
  }

  /// Literal values normalize to the same complete node within their kind.
  #[test]
  fn literal_values_erased() -> Result<(), NormalizerTestFailure> {
    for source in ["42\n", "99\n"] {
      check_statement(source, NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Int)))?;
    }
    Ok(())
  }

  /// Addition preserves both ordered operands.
  #[test]
  fn binary_add() -> Result<(), NormalizerTestFailure> {
    check_statement(
      "a + b\n",
      NormalizedNode::with_children(NodeKind::BinaryOp(BinOpKind::Add), vec![variable(0), variable(1)]),
    )
  }

  /// Comparison syntax uses positional operands without losing their order.
  #[test]
  fn binary_eq() -> Result<(), NormalizerTestFailure> {
    check_statement(
      "a == b\n",
      NormalizedNode::with_children(NodeKind::BinaryOp(BinOpKind::Eq), vec![variable(0), variable(1)]),
    )
  }

  /// Boolean conjunction retains its semantic operator kind.
  #[test]
  fn boolean_and() -> Result<(), NormalizerTestFailure> {
    check_statement(
      "a and b\n",
      NormalizedNode::with_children(NodeKind::BinaryOp(BinOpKind::And), vec![variable(0), variable(1)]),
    )
  }

  /// An unmapped operator retains both operands under the fallback operator kind.
  #[test]
  fn unknown_binary_op_falls_back_to_other() -> Result<(), NormalizerTestFailure> {
    check_statement(
      "a ** b\n",
      NormalizedNode::with_children(NodeKind::BinaryOp(BinOpKind::Other), vec![variable(0), variable(1)]),
    )
  }

  /// Logical negation retains exactly one operand.
  #[test]
  fn unary_not() -> Result<(), NormalizerTestFailure> {
    check_statement(
      "not x\n",
      NormalizedNode::with_children(NodeKind::UnaryOp(UnOpKind::Not), vec![variable(0)]),
    )
  }

  /// Arithmetic negation remains distinct from logical negation.
  #[test]
  fn unary_neg() -> Result<(), NormalizerTestFailure> {
    check_statement(
      "-x\n",
      NormalizedNode::with_children(NodeKind::UnaryOp(UnOpKind::Neg), vec![variable(0)]),
    )
  }

  /// Assignment retains the target before the assigned value.
  #[test]
  fn assignment_normalization() -> Result<(), NormalizerTestFailure> {
    check_statement(
      "x = 1\n",
      NormalizedNode::with_children(NodeKind::Assign, vec![
        variable(0),
        NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Int)),
      ]),
    )
  }

  /// A return value remains present inside its containing body.
  #[test]
  fn return_with_value() -> Result<(), NormalizerTestFailure> {
    check_function_body("def f():\n    return 42\n", vec![NormalizedNode::with_children(
      NodeKind::Return,
      vec![NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Int))],
    )])
  }

  /// A bare return has no fabricated return value.
  #[test]
  fn return_without_value() -> Result<(), NormalizerTestFailure> {
    check_function_body("def f():\n    return\n", vec![NormalizedNode::leaf(NodeKind::Return)])
  }

  /// Conditions precede their bodies, and absent alternatives retain the fixed `None` slot.
  #[test]
  fn conditional_and_while_children_preserve_order_and_absence() -> Result<(), NormalizerTestFailure> {
    let branch = NormalizedNode::with_children(NodeKind::Block, vec![NormalizedNode::with_children(NodeKind::Assign, vec![
      variable(1),
      NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Int)),
    ])]);
    for (input, kind, children) in [
      ("if x:\n    y = 1\nelse:\n    y = 2\n", NodeKind::If, vec![
        variable(0),
        branch.clone(),
        branch.clone(),
      ]),
      ("if x:\n    y = 1\n", NodeKind::If, vec![
        variable(0),
        branch.clone(),
        NormalizedNode::none(),
      ]),
      ("while x:\n    y = 1\n", NodeKind::While, vec![variable(0), branch]),
    ] {
      check_statement(input, NormalizedNode::with_children(kind, children))?;
    }
    Ok(())
  }

  /// A for loop retains its binding, iterable, and body in that order.
  #[test]
  fn for_loop() -> Result<(), NormalizerTestFailure> {
    check_statement(
      "for x in items:\n    pass\n",
      NormalizedNode::with_children(NodeKind::ForLoop, vec![
        variable(0),
        variable(1),
        NormalizedNode::with_children(NodeKind::Block, vec![NormalizedNode::leaf(NodeKind::Opaque)]),
      ]),
    )
  }

  /// Call arguments follow the callee, skip comments, and reuse repeated identifiers.
  #[test]
  fn call_with_args() -> Result<(), NormalizerTestFailure> {
    for (input, children) in [
      ("f(a, b)\n", vec![variable(0), variable(1), variable(2)]),
      ("f(\n    # before arguments\n    a,\n    # between arguments\n    b\n)\n", vec![
        variable(0),
        variable(1),
        variable(2),
      ]),
      ("f(a, a)\n", vec![variable(0), variable(1), variable(1)]),
    ] {
      check_statement(input, NormalizedNode::with_children(NodeKind::Call, children))?;
    }
    Ok(())
  }

  /// An argument-free call retains only its callee.
  #[test]
  fn call_no_args() -> Result<(), NormalizerTestFailure> {
    check_statement("f()\n", NormalizedNode::with_children(NodeKind::Call, vec![variable(0)]))
  }

  /// Configured comments are skipped while adjacent executable statements remain.
  #[test]
  fn skip_kinds_are_filtered() -> Result<(), NormalizerTestFailure> {
    check_statements("# comment\nx = 1\n", &test_mapping(), vec![NormalizedNode::with_children(
      NodeKind::Assign,
      vec![variable(0), NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Int))],
    )])
  }

  /// Malformed syntax remains representable through opaque subtrees.
  #[test]
  fn error_node_becomes_opaque() -> Result<(), NormalizerTestFailure> {
    let source = "((( @@@ )))\n";
    let tree = parse(source)?;
    let root = tree.root_node();
    let normalized = normalize_ts_node(&root, source.as_bytes(), &test_mapping(), &mut NormalizationContext::new())?;
    ensure(
      root.has_error() && has_opaque(&normalized),
      "malformed syntax retains its native parse-error observation and an opaque normalized subtree",
    )
    .map(drop)
    .map_err(|failure| NormalizerTestFailure::Malformed {
      tree,
      normalized: Box::new(normalized),
      source: failure,
    })
  }

  /// Recovery-inserted identifiers stay opaque and do not allocate variable placeholders.
  #[test]
  fn missing_identifiers_do_not_become_placeholders() -> Result<(), NormalizerTestFailure> {
    for (source, expected_missing, expected, next_index) in [
      ("if :\n    pass\n", true, NormalizedNode::leaf(NodeKind::Opaque), 0),
      ("if ready:\n    pass\n", false, variable(0), 1),
    ] {
      let tree = parse(source)?;
      let identifier = first_stmt(&tree)?
        .child_by_field_name("condition")
        .ok_or_else(|| NormalizerTestFailure::MissingNode {
          tree:      tree.clone(),
          selection: "the conditional identifier",
        })?;
      let mut context = NormalizationContext::new();
      let outcome = normalize_ts_node(&identifier, source.as_bytes(), &test_mapping(), &mut context);
      check_attempt(tree.clone(), context, outcome, |observed, placeholders| {
        ensure(
          identifier.kind() == "identifier"
            && identifier.is_missing() == expected_missing
            && matches!(*observed, Ok(ref normalized) if *normalized == expected)
            && placeholders.placeholder("after", PlaceholderKind::Variable) == next_index,
          "native missing identifiers remain opaque without allocating placeholders, while real identifiers retain normal mapping",
        )
        .map(drop)
      })?;
    }
    Ok(())
  }

  /// A block retains all statements under one shared placeholder context.
  #[test]
  fn block_normalization() -> Result<(), NormalizerTestFailure> {
    check_function_body("def f():\n    x = 1\n    y = 2\n", vec![
      NormalizedNode::with_children(NodeKind::Assign, vec![
        variable(0),
        NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Int)),
      ]),
      NormalizedNode::with_children(NodeKind::Assign, vec![
        variable(1),
        NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Int)),
      ]),
    ])
  }

  /// An unknown single-child wrapper normalizes directly to its child.
  #[test]
  fn single_child_unwrap() -> Result<(), NormalizerTestFailure> {
    check_statement("42\n", NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Int)))
  }

  /// A required identifier outside the supplied bytes returns its native range.
  #[test]
  fn required_identifier_rejects_missing_bytes() -> Result<(), NormalizerTestFailure> {
    let tree = parse("name\n")?;
    let identifier = first_expression(&tree)?;
    let expected_range = identifier.range();
    let mut context = NormalizationContext::new();
    let outcome = normalize_ts_node(&identifier, b"na", &test_mapping(), &mut context);
    check_attempt(tree, context, outcome, |observed, _| {
      ensure(
        matches!(*observed, Err(NormalizationError::Text(NodeTextError::OutOfBounds { ref input, range }))
          if input == b"na" && range == expected_range),
        "a missing identifier range is reported with the complete bytes instead of panicking or inventing a placeholder",
      )
      .map(drop)
    })
  }

  /// Invalid identifier and operator text preserve the native UTF-8 diagnostic.
  #[test]
  fn required_text_retains_utf8_failures() -> Result<(), NormalizerTestFailure> {
    for (parsed, bytes, expected_bytes) in [
      ("name\n", b"\xffame\n".as_slice(), 0..4),
      ("a+b\n", b"a\xffb\n".as_slice(), 1..2),
    ] {
      let tree = parse(parsed)?;
      let expression = first_expression(&tree)?;
      let mut context = NormalizationContext::new();
      let outcome = normalize_ts_node(&expression, bytes, &test_mapping(), &mut context);
      check_attempt(tree, context, outcome, |observed, _| {
        ensure(
          matches!(*observed, Err(NormalizationError::Text(NodeTextError::Utf8 { ref input, range, source }))
            if input == bytes && (range.start_byte, range.end_byte) == (expected_bytes.start, expected_bytes.end)
              && source.valid_up_to() == 0 && source.error_len() == Some(1)),
          "unreadable identifiers and operators retain their input, selected range, and native UTF-8 error",
        )
        .map(drop)
      })?;
    }
    Ok(())
  }

  /// Failed later children preserve earlier normalized siblings and placeholder state.
  #[test]
  fn failed_child_retains_completed_prefix_and_context() -> Result<(), NormalizerTestFailure> {
    let tree = parse("first\nsecond\n")?;
    let root_range = tree.root_node().range();
    let bytes = b"first\n\xffxxxxx\n";
    let mut context = NormalizationContext::new();
    let outcome = normalize_ts_node(&tree.root_node(), bytes, &test_mapping(), &mut context);
    check_attempt(tree, context, outcome, |observed, placeholders| {
      let Err(NormalizationError::Children {
        ref kind,
        range,
        ref completed,
        source: ref child_error,
      }) = *observed
      else {
        return ensure(false, "the second statement must fail after the first statement was normalized").map(drop);
      };
      let preserved = kind == "module"
        && range == root_range
        && *completed == [variable(0)]
        && matches!(**child_error, NormalizationError::Children { kind: ref child_kind, completed: ref child_completed, source: ref text_error, .. }
          if child_kind == "expression_statement" && child_completed.is_empty()
            && matches!(**text_error, NormalizationError::Text(NodeTextError::Utf8 { ref input, range: text_range, source })
              if input == bytes && text_range.start_byte == 6 && text_range.end_byte == 12
                && source.valid_up_to() == 0 && source.error_len() == Some(1)));
      ensure(
        preserved
          && placeholders.placeholder("first", PlaceholderKind::Variable) == 0
          && placeholders.placeholder("after", PlaceholderKind::Variable) == 1,
        "the failed child retains completed siblings, the nested native failure, and the caller's established placeholders",
      )
      .map(drop)
    })
  }

  /// Failed callees, arguments, and match subjects retain their parent and completed normalization
  /// state.
  #[test]
  fn failed_structural_child_retains_parent_and_completed_prefix() -> Result<(), NormalizerTestFailure> {
    let call_tree = parse("callee(first, second)\n")?;
    let call = first_expression(&call_tree)?;
    let match_tree = parse("match subject:\n    case _:\n        pass\n")?;
    let matched = first_stmt(&match_tree)?;
    for (tree, parent, bytes, (start_byte, end_byte), expected_completed, next_index) in [
      (&call_tree, call, b"\xffallee(first, second)\n".as_slice(), (0, 6), vec![], 1),
      (
        &call_tree,
        call,
        b"callee(\xffirst, second)\n".as_slice(),
        (7, 12),
        vec![variable(1)],
        2,
      ),
      (
        &call_tree,
        call,
        b"callee(first, \xffecond)\n".as_slice(),
        (14, 20),
        vec![variable(1), variable(2)],
        3,
      ),
      (
        &match_tree,
        matched,
        b"match \xffubject:\n    case _:\n        pass\n".as_slice(),
        (6, 13),
        vec![],
        1,
      ),
    ] {
      let expected_range = tree_sitter::Range {
        start_byte,
        end_byte,
        start_point: tree_sitter::Point::new(0, start_byte),
        end_point: tree_sitter::Point::new(0, end_byte),
      };
      let mut context = NormalizationContext::new();
      let established_index = context.placeholder("established", PlaceholderKind::Variable);
      let outcome = normalize_ts_node(&parent, bytes, &test_mapping(), &mut context);
      check_attempt(tree.clone(), context, outcome, |observed, placeholders| {
        let preserved = matches!(*observed, Err(NormalizationError::Children {
          ref kind, range, ref completed, ref source,
        }) if kind == parent.kind() && range == parent.range() && *completed == expected_completed
          && matches!(**source, NormalizationError::Text(NodeTextError::Utf8 { ref input, range: text_range, source: failure })
            if input == bytes && text_range == expected_range
              && failure.valid_up_to() == 0 && failure.error_len() == Some(1)));
        ensure(
          preserved
            && established_index == 0
            && placeholders.placeholder("established", PlaceholderKind::Variable) == 0
            && placeholders.placeholder("after", PlaceholderKind::Variable) == next_index,
          "structural child failures retain their parent, completed children, native text failure, and established placeholders without \
           normalizing later children",
        )
        .map(drop)
      })?;
    }
    Ok(())
  }

  /// Opaque and skipped nodes do not require text that their mapping never consumes.
  #[test]
  fn opaque_and_skipped_nodes_do_not_decode_unused_text() -> Result<(), NormalizerTestFailure> {
    let tree = parse("name\n")?;
    let statement = first_stmt(&tree)?;
    for mapping in [
      NodeMapping::new().opaque(&["expression_statement"]),
      NodeMapping::new().skip(&["expression_statement"]),
    ] {
      let normalized = normalize_ts_node(&statement, b"\xff", &mapping, &mut NormalizationContext::new())?;
      ensure_eq(
        normalized,
        NormalizedNode::leaf(NodeKind::Opaque),
        "opaque and skipped nodes do not read unused source bytes",
      )
      .map(drop)
      .map_err(Box::new)?;
    }
    let identifier = first_expression(&tree)?;
    let normalized = normalize_ts_node(&identifier, b"name\n\xff", &test_mapping(), &mut NormalizationContext::new())?;
    ensure_eq(normalized, variable(0), "identifier normalization reads only its own byte range")
      .map(drop)
      .map_err(Box::new)
      .map_err(NormalizerTestFailure::from)
  }
}
