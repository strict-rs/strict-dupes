//! Table-driven [`NodeMapping`] from tree-sitter grammar node kinds to
//! `dupes-core` concepts — the extension point each language populates.

use std::collections::HashMap;
use std::collections::HashSet;

use dupes_core::node::BinOpKind;
use dupes_core::node::LiteralKind;
use dupes_core::node::NodeKind;
use dupes_core::node::UnOpKind;

/// Table-driven mapping from tree-sitter node kinds to dupes-core concepts.
///
/// Each language populates its own instance with the relevant node kind strings
/// from its tree-sitter grammar. The normalizer and extractor use this mapping
/// to convert tree-sitter CST nodes into `NormalizedNode` trees.
/// Equality compares every grammar category and semantic mapping, independent of insertion order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeMapping {
  /// Node kinds that represent identifiers (variables, function names, etc.).
  pub identifier_kinds:   HashSet<&'static str>,
  /// Node kinds that represent literals, mapped to their `LiteralKind`.
  pub literal_kinds:      HashMap<&'static str, LiteralKind>,
  /// Node kinds for binary operators, mapped to `BinOpKind`.
  pub binary_op_map:      HashMap<&'static str, BinOpKind>,
  /// Node kinds for unary operators, mapped to `UnOpKind`.
  pub unary_op_map:       HashMap<&'static str, UnOpKind>,
  /// Node kinds to skip entirely (e.g., comments, decorators).
  pub skip_kinds:         HashSet<&'static str>,
  /// Node kinds to treat as opaque leaves (no recursive normalization).
  pub opaque_kinds:       HashSet<&'static str>,
  /// Node kinds representing block/suite constructs.
  pub block_kinds:        HashSet<&'static str>,
  /// Node kinds representing function/method calls.
  pub call_kinds:         HashSet<&'static str>,
  /// Node kinds representing return statements.
  pub return_kinds:       HashSet<&'static str>,
  /// Node kinds representing if/conditional constructs.
  pub if_kinds:           HashSet<&'static str>,
  /// Node kinds representing infinite loop constructs.
  pub loop_kinds:         HashSet<&'static str>,
  /// Node kinds representing for-loop constructs.
  pub for_kinds:          HashSet<&'static str>,
  /// Node kinds representing while-loop constructs.
  pub while_kinds:        HashSet<&'static str>,
  /// Node kinds representing match/switch constructs.
  pub match_kinds:        HashSet<&'static str>,
  /// Node kinds representing assignment statements.
  pub assignment_kinds:   HashSet<&'static str>,
  /// Node kinds representing function definitions.
  pub function_def_kinds: HashSet<&'static str>,
  /// Node kinds representing binary operator expressions (e.g., `"binary_operator"`,
  /// `"binary_expression"`, `"boolean_operator"`, `"comparison_operator"`).
  /// The operator text is looked up in `binary_op_map`.
  pub binary_op_kinds:    HashSet<&'static str>,
  /// Node kinds representing unary operator expressions (e.g., `"unary_operator"`,
  /// `"unary_expression"`, `"not_operator"`).
  /// The operator text is looked up in `unary_op_map`.
  pub unary_op_kinds:     HashSet<&'static str>,
  /// Node kinds representing match/case arm entries within a match statement.
  /// Used for fixed-position child extraction: `[pattern, guard_or_None, body]`.
  pub match_arm_kinds:    HashSet<&'static str>,
  /// Direct node-kind-to-`NodeKind` mappings. Named children are recursively
  /// normalized and attached as children. Zero-child nodes produce leaves.
  ///
  /// Use this for constructs that map directly to a `NodeKind` variant and
  /// whose children should be normalized generically (e.g., `break_statement` →
  /// `Break`, `await` → `Await [child]`, `tuple` → `Tuple [elem, ...]`).
  pub node_kinds:         HashMap<&'static str, NodeKind>,
}

/// Define builders that extend a collection of grammar node kinds.
macro_rules! set_builder {
    ($(
        $(#[$meta:meta])*
        $method:ident => $field:ident;
    )*) => {
        $(
            $(#[$meta])*
            #[must_use]
            pub fn $method(mut self, kinds: &[&'static str]) -> Self {
                extend_set(&mut self.$field, kinds);
                self
            }
        )*
    };
}

/// Define builders that assign semantic meanings to grammar node kinds.
macro_rules! map_builder {
    ($(
        $(#[$meta:meta])*
        $method:ident($value:ty) => $field:ident;
    )*) => {
        $(
            $(#[$meta])*
            #[must_use]
            pub fn $method(mut self, mappings: &[(&'static str, $value)]) -> Self {
                extend_map(&mut self.$field, mappings);
                self
            }
        )*
    };
}

impl NodeMapping {
  /// Create an empty mapping. Use the builder methods to populate it.
  #[must_use]
  #[allow(
    clippy::single_call_fn,
    reason = "Empty mapping construction is the language-neutral baseline for every grammar builder"
  )]
  pub fn new() -> Self {
    Self::default()
  }

  set_builder! {
      /// Add identifier node kinds.
      identifiers => identifier_kinds;
      /// Add node kinds to skip entirely.
      skip => skip_kinds;
      /// Add node kinds to treat as opaque leaves.
      opaque => opaque_kinds;
      /// Add block/suite node kinds.
      blocks => block_kinds;
      /// Add call node kinds.
      calls => call_kinds;
      /// Add return statement node kinds.
      returns => return_kinds;
      /// Add if/conditional node kinds.
      ifs => if_kinds;
      /// Add infinite loop node kinds.
      loops => loop_kinds;
      /// Add for-loop node kinds.
      for_loops => for_kinds;
      /// Add while-loop node kinds.
      while_loops => while_kinds;
      /// Add match/switch node kinds.
      matches => match_kinds;
      /// Add assignment node kinds.
      assignments => assignment_kinds;
      /// Add function definition node kinds.
      function_defs => function_def_kinds;
      /// Add binary operator expression node kinds (e.g., `"binary_operator"`,
      /// `"binary_expression"`). These are the tree-sitter node kinds that contain
      /// a binary operation; the operator text is looked up in `binary_op_map`.
      binary_op_kinds => binary_op_kinds;
      /// Add unary operator expression node kinds (e.g., `"unary_operator"`,
      /// `"not_operator"`). These are the tree-sitter node kinds that contain
      /// a unary operation; the operator text is looked up in `unary_op_map`.
      unary_op_kinds => unary_op_kinds;
      /// Add match/case arm node kinds for fixed-position extraction.
      match_arms => match_arm_kinds;
  }

  map_builder! {
      /// Add literal node kinds with their `LiteralKind`.
      literals(LiteralKind) => literal_kinds;
      /// Add binary operator mappings (operator text → `BinOpKind`).
      binary_ops(BinOpKind) => binary_op_map;
      /// Add unary operator mappings (operator text → `UnOpKind`).
      unary_ops(UnOpKind) => unary_op_map;
      /// Add direct node-kind-to-`NodeKind` mappings.
      ///
      /// Named children are recursively normalized. Zero-child nodes produce leaves.
      /// Use this for constructs like `break_statement` → `Break`, `await` → `Await`.
      node_kinds(NodeKind) => node_kinds;
  }
}

/// Accumulate grammar kinds while retaining previous builder inputs.
fn extend_set(set: &mut HashSet<&'static str>, values: &[&'static str]) {
  set.extend(values.iter().copied());
}

/// Assign mappings, replacing earlier values for a repeated grammar kind.
fn extend_map<Value: Clone>(map: &mut HashMap<&'static str, Value>, values: &[(&'static str, Value)]) {
  map.extend(values.iter().cloned());
}

#[cfg(test)]
mod tests {
  use std::collections::HashMap;
  use std::collections::HashSet;

  use dupes_core::node::BinOpKind;
  use dupes_core::node::LiteralKind;
  use dupes_core::node::NodeKind;
  use dupes_core::node::UnOpKind;
  use strict_test_support::ComparisonFailure;
  use strict_test_support::ensure_eq;

  use super::NodeMapping;

  /// Empty construction supplies no implicit language-specific classification.
  #[test]
  fn empty_mapping() -> Result<(), Box<ComparisonFailure<NodeMapping, NodeMapping>>> {
    let mut expected = NodeMapping {
      identifier_kinds:   HashSet::new(),
      literal_kinds:      HashMap::new(),
      binary_op_map:      HashMap::new(),
      unary_op_map:       HashMap::new(),
      skip_kinds:         HashSet::new(),
      opaque_kinds:       HashSet::new(),
      block_kinds:        HashSet::new(),
      call_kinds:         HashSet::new(),
      return_kinds:       HashSet::new(),
      if_kinds:           HashSet::new(),
      loop_kinds:         HashSet::new(),
      for_kinds:          HashSet::new(),
      while_kinds:        HashSet::new(),
      match_kinds:        HashSet::new(),
      assignment_kinds:   HashSet::new(),
      function_def_kinds: HashSet::new(),
      binary_op_kinds:    HashSet::new(),
      unary_op_kinds:     HashSet::new(),
      match_arm_kinds:    HashSet::new(),
      node_kinds:         HashMap::new(),
    };
    for mapping in [NodeMapping::new(), NodeMapping::default()] {
      let (_, retained_expected) =
        ensure_eq(mapping, expected, "new and default mappings leave every grammar category empty").map_err(Box::new)?;
      expected = retained_expected;
    }
    Ok(())
  }

  /// Every builder populates only its declared semantic category.
  #[test]
  fn builder_api() -> Result<(), Box<ComparisonFailure<NodeMapping, NodeMapping>>> {
    let mapping = NodeMapping::new()
      .identifiers(&["identifier", "name"])
      .literals(&[("integer", LiteralKind::Int), ("string", LiteralKind::Str)])
      .binary_ops(&[("+", BinOpKind::Add), ("-", BinOpKind::Sub)])
      .unary_ops(&[("not", UnOpKind::Not)])
      .skip(&["comment"])
      .opaque(&["ERROR"])
      .blocks(&["block"])
      .calls(&["call"])
      .returns(&["return_statement"])
      .ifs(&["if_statement"])
      .loops(&["loop_statement"])
      .for_loops(&["for_statement"])
      .while_loops(&["while_statement"])
      .matches(&["match_statement"])
      .assignments(&["assignment"])
      .function_defs(&["function_definition"])
      .binary_op_kinds(&["binary_operator"])
      .unary_op_kinds(&["unary_operator"])
      .match_arms(&["case_clause"])
      .node_kinds(&[("break_statement", NodeKind::Break)]);

    let expected = NodeMapping {
      identifier_kinds:   HashSet::from(["identifier", "name"]),
      literal_kinds:      HashMap::from([("integer", LiteralKind::Int), ("string", LiteralKind::Str)]),
      binary_op_map:      HashMap::from([("+", BinOpKind::Add), ("-", BinOpKind::Sub)]),
      unary_op_map:       HashMap::from([("not", UnOpKind::Not)]),
      skip_kinds:         HashSet::from(["comment"]),
      opaque_kinds:       HashSet::from(["ERROR"]),
      block_kinds:        HashSet::from(["block"]),
      call_kinds:         HashSet::from(["call"]),
      return_kinds:       HashSet::from(["return_statement"]),
      if_kinds:           HashSet::from(["if_statement"]),
      loop_kinds:         HashSet::from(["loop_statement"]),
      for_kinds:          HashSet::from(["for_statement"]),
      while_kinds:        HashSet::from(["while_statement"]),
      match_kinds:        HashSet::from(["match_statement"]),
      assignment_kinds:   HashSet::from(["assignment"]),
      function_def_kinds: HashSet::from(["function_definition"]),
      binary_op_kinds:    HashSet::from(["binary_operator"]),
      unary_op_kinds:     HashSet::from(["unary_operator"]),
      match_arm_kinds:    HashSet::from(["case_clause"]),
      node_kinds:         HashMap::from([("break_statement", NodeKind::Break)]),
    };
    ensure_eq(
      mapping,
      expected,
      "builders populate every requested grammar category independently",
    )
    .map(drop)
    .map_err(Box::new)
  }

  /// Incremental configuration accumulates kinds and replaces repeated mappings.
  #[test]
  fn repeated_builders_preserve_existing_kinds_and_replace_mapped_values() -> Result<(), Box<ComparisonFailure<NodeMapping, NodeMapping>>> {
    let mapping = NodeMapping::new()
      .identifiers(&["identifier"])
      .identifiers(&["name", "identifier"])
      .identifiers(&[])
      .literals(&[("integer", LiteralKind::Int), ("string", LiteralKind::Str)])
      .literals(&[("integer", LiteralKind::Float)])
      .literals(&[]);
    let expected = NodeMapping {
      identifier_kinds: HashSet::from(["identifier", "name"]),
      literal_kinds: HashMap::from([("integer", LiteralKind::Float), ("string", LiteralKind::Str)]),
      ..NodeMapping::default()
    };
    ensure_eq(
      mapping,
      expected,
      "repeated builders retain unrelated categories and replace the requested mapped value",
    )
    .map(drop)
    .map_err(Box::new)
  }
}
