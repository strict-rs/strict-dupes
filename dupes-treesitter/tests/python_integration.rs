//! Tree-sitter bridge integration exercised with Python grammar fixtures:
//! query-based extraction and mapping-driven normalization.

#[cfg(test)]
mod tests {
  use std::path::Path;

  use dupes_core::code_unit::CodeUnit;
  use dupes_core::code_unit::CodeUnitKind;
  use dupes_core::config::AnalysisConfig;
  use dupes_core::node::BinOpKind;
  use dupes_core::node::LiteralKind;
  use dupes_core::node::NodeKind;
  use dupes_core::node::NormalizationContext;
  use dupes_core::node::NormalizedNode;
  use dupes_core::node::PlaceholderKind;
  use dupes_core::node::UnOpKind;
  use dupes_core::node::count_nodes;
  use dupes_treesitter::extractor::ExtractionError;
  use dupes_treesitter::mapping::NodeMapping;
  use dupes_treesitter::normalizer::NormalizationError;
  use dupes_treesitter::normalizer::normalize_ts_node;
  use strict_test_support::TestFailure;
  use strict_test_support::ensure;

  /// Capture complete function definitions and their signature and body parts.
  const FUNCTION_QUERY: &str = "
    (function_definition
        name: (identifier) @name
        parameters: (parameters) @parameters
        body: (block) @body
    ) @definition
    ";

  /// Preserve native setup errors and complete observed values in test failures.
  #[derive(Debug, thiserror::Error)]
  enum BridgeTestFailure {
    /// The parser rejected the fixture grammar.
    #[error(transparent)]
    Language(#[from] tree_sitter::LanguageError),
    /// The extraction query could not be compiled.
    #[error(transparent)]
    Query(#[from] tree_sitter::QueryError),
    /// Required text could not be normalized.
    #[error(transparent)]
    Normalization(#[from] NormalizationError),
    /// A captured definition could not be extracted.
    #[error(transparent)]
    Extraction(#[from] ExtractionError),
    /// The parser produced no tree for the supplied fixture.
    #[error("the parser returned no tree for {input:?}")]
    NoTree {
      /// Complete source supplied to the parser.
      input: String,
    },
    /// The parsed fixture contained no function body.
    #[error("the fixture has no function body: {tree:?}")]
    MissingBody {
      /// Native tree returned for the fixture.
      tree: tree_sitter::Tree,
    },
    /// Normalization did not satisfy the expected relation.
    #[error("{source}; left normalized tree: {left:?}; right: {right:?}")]
    Normalized {
      /// Complete normalized result on the left of the comparison.
      left:   Box<NormalizedNode>,
      /// Complete normalized result on the right of the comparison.
      right:  Box<NormalizedNode>,
      /// Failed semantic expectation.
      source: TestFailure,
    },
    /// Code-unit extraction did not satisfy its semantic contract.
    #[error("{source}; input: {input:?}; extracted units: {units:?}")]
    Units {
      /// Complete source supplied to extraction.
      input:  String,
      /// Complete units returned by extraction.
      units:  Vec<CodeUnit>,
      /// Failed semantic expectation.
      source: TestFailure,
    },
    /// A threshold pair failed to admit and then reject the same definition.
    #[error("{source}; input: {input:?}; configurations: {configs:?}; extraction outcomes: {outcomes:?}")]
    Thresholds {
      /// Complete source used by both extraction attempts.
      input:    String,
      /// Permissive and restrictive configurations in execution order.
      configs:  [AnalysisConfig; 2],
      /// Both complete extraction outcomes, including native failures.
      outcomes: Box<[ExtractionResult; 2]>,
      /// Failed semantic expectation.
      source:   Box<TestFailure>,
    },
    /// Malformed syntax lost its native or normalized error signal.
    #[error("{source}; native tree: {tree:?}; normalized tree: {normalized:?}")]
    Malformed {
      /// Native parse tree returned for malformed source.
      tree:       tree_sitter::Tree,
      /// Complete normalized representation of that tree.
      normalized: Box<NormalizedNode>,
      /// Failed semantic expectation.
      source:     TestFailure,
    },
  }

  /// Complete query-extraction result, retaining native setup and extraction failures.
  type ExtractionResult = Result<Vec<CodeUnit>, BridgeTestFailure>;

  /// Build a minimal Python `NodeMapping` for testing the tree-sitter normalization layer.
  ///
  /// NOTE: The production Python mapping lives in `dupes_python::python_mapping()` and is
  /// more comprehensive (augmented assignments, containers, `node_kinds` for break/continue/
  /// await/yield, etc.). This test-only version covers just enough for normalizer unit tests.
  fn python_mapping() -> NodeMapping {
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
        ("/", BinOpKind::Div),
        ("%", BinOpKind::Rem),
        ("==", BinOpKind::Eq),
        ("!=", BinOpKind::Ne),
        ("<", BinOpKind::Lt),
        (">", BinOpKind::Gt),
        ("<=", BinOpKind::Le),
        (">=", BinOpKind::Ge),
        ("and", BinOpKind::And),
        ("or", BinOpKind::Or),
        ("&", BinOpKind::BitAnd),
        ("|", BinOpKind::BitOr),
        ("^", BinOpKind::BitXor),
        ("<<", BinOpKind::Shl),
        (">>", BinOpKind::Shr),
      ])
      .unary_ops(&[("not", UnOpKind::Not), ("-", UnOpKind::Neg), ("~", UnOpKind::Other)])
      .skip(&["comment", "decorator"])
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
      .node_kinds(&[
        ("break_statement", NodeKind::Break),
        ("continue_statement", NodeKind::Continue),
        ("tuple", NodeKind::Tuple),
        ("list", NodeKind::Array),
      ])
  }

  /// Parse Python source and return the tree.
  fn parse_python(source: &str) -> Result<tree_sitter::Tree, BridgeTestFailure> {
    let mut parser = tree_sitter::Parser::new();
    let language = tree_sitter_python::LANGUAGE;
    parser.set_language(&language.into())?;
    parser.parse(source, None).ok_or_else(|| BridgeTestFailure::NoTree {
      input: source.to_owned()
    })
  }

  /// Locate a function body while retaining the parsed tree's node lifetime.
  fn find_body<'tree>(node: &tree_sitter::Node<'tree>) -> Option<tree_sitter::Node<'tree>> {
    if node.kind() == "function_definition" {
      return node.child_by_field_name("body");
    }
    let cursor = &mut node.walk();
    for child in node.named_children(cursor) {
      if let Some(body) = find_body(&child) {
        return Some(body);
      }
    }
    None
  }

  /// Find a semantic kind anywhere in a complete normalized tree.
  fn contains_kind(node: &NormalizedNode, kind: &NodeKind) -> bool {
    if &node.kind == kind {
      return true;
    }
    node.children.iter().any(|child| contains_kind(child, kind))
  }

  /// Normalize a Python function body (first `function_definition`'s body block).
  fn normalize_python_body(source: &str) -> Result<NormalizedNode, BridgeTestFailure> {
    let tree = parse_python(source)?;
    let mapping = python_mapping();
    let mut context = NormalizationContext::new();
    let root = tree.root_node();

    let body = find_body(&root).ok_or_else(|| BridgeTestFailure::MissingBody {
      tree: tree.clone()
    })?;
    normalize_ts_node(&body, source.as_bytes(), &mapping, &mut context).map_err(BridgeTestFailure::from)
  }

  /// Normalize complete source through the bridge's public normalization boundary.
  fn normalize_python_source(source: &str) -> Result<NormalizedNode, BridgeTestFailure> {
    let tree = parse_python(source)?;
    normalize_ts_node(
      &tree.root_node(),
      source.as_bytes(),
      &python_mapping(),
      &mut NormalizationContext::new(),
    )
    .map_err(BridgeTestFailure::from)
  }

  /// Construct an extraction threshold configuration for a fixture.
  const fn config(min_nodes: usize, min_lines: usize) -> AnalysisConfig {
    AnalysisConfig {
      min_nodes,
      min_lines,
    }
  }

  /// Extract fixture functions through a compiled query and its mapping.
  fn extract_functions(source: &str, config: AnalysisConfig) -> ExtractionResult {
    let tree = parse_python(source)?;
    let mapping = python_mapping();
    let query = tree_sitter::Query::new(&tree_sitter_python::LANGUAGE.into(), FUNCTION_QUERY)?;

    let extractor = dupes_treesitter::CodeUnitExtractor::new(&query, &mapping, |_| CodeUnitKind::Function, |_, _| false);
    extractor
      .extract(&tree, source.as_bytes(), Path::new("test.py"), config)
      .map_err(BridgeTestFailure::from)
  }

  /// Compare complete normalized trees while retaining both on failure.
  fn check_normalized_equal(left: NormalizedNode, right: NormalizedNode) -> Result<(), BridgeTestFailure> {
    ensure(left == right, "normalized trees preserve the expected kinds and ordered children").map_err(|source| {
      BridgeTestFailure::Normalized {
        left: Box::new(left),
        right: Box::new(right),
        source,
      }
    })
  }

  /// Check extraction while retaining every returned unit on assertion failure.
  fn check_units(input: &str, check: impl FnOnce(&[CodeUnit]) -> Result<(), TestFailure>) -> Result<(), BridgeTestFailure> {
    let units = extract_functions(input, config(1, 1))?;
    check(&units).map_err(|source| BridgeTestFailure::Units {
      input: input.to_owned(),
      units,
      source,
    })
  }

  /// Construct an expected variable placeholder by encounter order.
  const fn variable(index: usize) -> NormalizedNode {
    NormalizedNode::leaf(NodeKind::Placeholder(PlaceholderKind::Variable, index))
  }

  /// Assignment preserves its binding before its literal value.
  #[test]
  fn identifier_normalization() -> Result<(), BridgeTestFailure> {
    check_normalized_equal(
      normalize_python_source("x = 1\n")?,
      NormalizedNode::with_children(NodeKind::Assign, vec![
        variable(0),
        NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Int)),
      ]),
    )
  }

  /// Renaming identifiers preserves the complete normalized body.
  #[test]
  fn renamed_variables_produce_identical_bodies() -> Result<(), BridgeTestFailure> {
    let source_a = "def foo(a, b):\n    return a + b\n";
    let source_b = "def bar(x, y):\n    return x + y\n";

    check_normalized_equal(normalize_python_body(source_a)?, normalize_python_body(source_b)?)
  }

  /// Changing the arithmetic operation changes the normalized body.
  #[test]
  fn different_structure_produces_different_trees() -> Result<(), BridgeTestFailure> {
    let source_add = "def foo(a, b):\n    return a + b\n";
    let source_mul = "def foo(a, b):\n    return a * b\n";

    let left = normalize_python_body(source_add)?;
    let right = normalize_python_body(source_mul)?;
    ensure(left != right, "different operators produce different normalized trees").map_err(|source| BridgeTestFailure::Normalized {
      left: Box::new(left),
      right: Box::new(right),
      source,
    })
  }

  /// Literal normalization preserves kind while discarding value for comparison.
  #[test]
  fn literal_kind_preserved_value_erased() -> Result<(), BridgeTestFailure> {
    for source in ["42\n", "99\n"] {
      check_normalized_equal(
        normalize_python_source(source)?,
        NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Int)),
      )?;
    }
    Ok(())
  }

  /// Addition retains both operands in source order.
  #[test]
  fn binary_operator_detection() -> Result<(), BridgeTestFailure> {
    check_normalized_equal(
      normalize_python_source("a + b\n")?,
      NormalizedNode::with_children(NodeKind::BinaryOp(BinOpKind::Add), vec![variable(0), variable(1)]),
    )
  }

  /// A conditional retains its condition and both branch bodies.
  #[test]
  fn if_else_normalization() -> Result<(), BridgeTestFailure> {
    let branch = NormalizedNode::with_children(NodeKind::Block, vec![NormalizedNode::with_children(NodeKind::Assign, vec![
      variable(1),
      NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Int)),
    ])]);
    check_normalized_equal(
      normalize_python_source("if x:\n    y = 1\nelse:\n    y = 2\n")?,
      NormalizedNode::with_children(NodeKind::If, vec![variable(0), branch.clone(), branch]),
    )
  }

  /// Query captures preserve function order, names, source paths, and definition spans.
  #[test]
  fn code_unit_extraction() -> Result<(), BridgeTestFailure> {
    let source = "
def add(a, b):
    result = a + b
    return result

def subtract(a, b):
    result = a - b
    return result
";
    check_units(source, |units| {
      let observed: Vec<_> = units
        .iter()
        .map(|unit| (unit.name.as_str(), unit.kind, unit.file.as_path(), unit.line_start, unit.line_end))
        .collect();
      ensure(
        observed
          == [
            ("add", CodeUnitKind::Function, Path::new("test.py"), 2, 4),
            ("subtract", CodeUnitKind::Function, Path::new("test.py"), 6, 8),
          ],
        "extraction retains each definition's identity and one-based source span",
      )
    })
  }

  /// Node and line thresholds admit a definition before excluding it at a higher floor.
  #[test]
  fn extraction_thresholds_admit_and_reject_the_same_definition() -> Result<(), BridgeTestFailure> {
    for (input, restrictive) in [
      ("def tiny():\n    pass\n", config(100, 1)),
      ("def one_liner(): return 1\n", config(1, 5)),
    ] {
      let configs = [config(1, 1), restrictive];
      let outcomes = configs.map(|settings| extract_functions(input, settings));
      ensure(
        matches!(&outcomes, [Ok(admitted), Ok(rejected)] if admitted.len() == 1 && rejected.is_empty()),
        "both extraction attempts succeed and only the lower floor admits the definition",
      )
      .map_err(|source| BridgeTestFailure::Thresholds {
        input: input.to_owned(),
        configs,
        outcomes: Box::new(outcomes),
        source: Box::new(source),
      })?;
    }
    Ok(())
  }

  /// Captured function fingerprints preserve renaming while distinguishing changed operators.
  #[test]
  fn captured_fingerprints_track_normalized_behavior() -> Result<(), BridgeTestFailure> {
    for (input, expected_equal) in [
      (
        "
def add(a, b):
    result = a + b
    return result

def add2(x, y):
    result = x + y
    return result
",
        true,
      ),
      (
        "
def add(a, b):
    return a + b

def mul(a, b):
    return a * b
",
        false,
      ),
    ] {
      check_units(input, |units| {
        ensure(
          matches!(units, [first, second] if (first.fingerprint == second.fingerprint) == expected_equal),
          "both complete captures retain their required fingerprint relation",
        )
      })?;
    }
    Ok(())
  }

  /// Malformed syntax remains visible as native errors and opaque normalized nodes.
  #[test]
  fn error_node_becomes_opaque() -> Result<(), BridgeTestFailure> {
    // Malformed Python source — tree-sitter will produce ERROR nodes
    // Use severely broken syntax to force ERROR node creation
    let source = "((( @@@ )))  def\n";
    let tree = parse_python(source)?;
    let mapping = python_mapping();
    let mut context = NormalizationContext::new();

    let root = tree.root_node();
    let normalized = normalize_ts_node(&root, source.as_bytes(), &mapping, &mut context)?;
    ensure(
      root.has_error() && contains_kind(&normalized, &NodeKind::Opaque),
      "malformed source retains native parse errors and an opaque normalized subtree",
    )
    .map_err(|failure| BridgeTestFailure::Malformed {
      tree,
      normalized: Box::new(normalized),
      source: failure,
    })
  }

  /// A nested call remains an argument with its own callee and argument.
  #[test]
  fn nested_calls() -> Result<(), BridgeTestFailure> {
    check_normalized_equal(
      normalize_python_source("f(g(x))\n")?,
      NormalizedNode::with_children(NodeKind::Call, vec![
        variable(0),
        NormalizedNode::with_children(NodeKind::Call, vec![variable(1), variable(2)]),
      ]),
    )
  }

  /// A no-op body retains its block and opaque statement as countable syntax.
  #[test]
  fn empty_function_body() -> Result<(), BridgeTestFailure> {
    let source = "def nothing():\n    pass\n";
    let body = normalize_python_body(source)?;
    let expected = NormalizedNode::with_children(NodeKind::Block, vec![NormalizedNode::leaf(NodeKind::Opaque)]);
    ensure(
      body == expected && count_nodes(&body) == 2,
      "a no-op body retains its complete two-node normalized tree",
    )
    .map_err(|failure| BridgeTestFailure::Normalized {
      left:   Box::new(body),
      right:  Box::new(expected),
      source: failure,
    })
  }

  /// A while condition precedes its body and shares the identifier context with it.
  #[test]
  fn while_loop_normalization() -> Result<(), BridgeTestFailure> {
    check_normalized_equal(
      normalize_python_source("while x:\n    y = 1\n")?,
      NormalizedNode::with_children(NodeKind::While, vec![
        variable(0),
        NormalizedNode::with_children(NodeKind::Block, vec![NormalizedNode::with_children(NodeKind::Assign, vec![
          variable(1),
          NormalizedNode::leaf(NodeKind::Literal(LiteralKind::Int)),
        ])]),
      ]),
    )
  }

  /// For-loop bindings, iterables, and nested calls retain their shared identities.
  #[test]
  fn for_loop_normalization() -> Result<(), BridgeTestFailure> {
    check_normalized_equal(
      normalize_python_source("for x in items:\n    print(x)\n")?,
      NormalizedNode::with_children(NodeKind::ForLoop, vec![
        variable(0),
        variable(1),
        NormalizedNode::with_children(NodeKind::Block, vec![NormalizedNode::with_children(NodeKind::Call, vec![
          variable(2),
          variable(0),
        ])]),
      ]),
    )
  }

  /// Direct kind mappings preserve a break statement inside the loop body.
  #[test]
  fn node_kinds_mapping_produces_correct_kind() -> Result<(), BridgeTestFailure> {
    check_normalized_equal(
      normalize_python_source("for x in items:\n    break\n")?,
      NormalizedNode::with_children(NodeKind::ForLoop, vec![
        variable(0),
        variable(1),
        NormalizedNode::with_children(NodeKind::Block, vec![NormalizedNode::leaf(NodeKind::Break)]),
      ]),
    )
  }
}
